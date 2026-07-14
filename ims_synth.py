#!/usr/bin/env python3
"""
Synthetic IMS Observability Data Generator
==========================================
Companion to gnb_synth.py / core_synth.py, modelling a typical Open5GS
IMS lab stack: Kamailio P/I/S-CSCF, PyHSS (Cx/Diameter), RTPEngine,
BIND DNS. Same design principles:
  1. SIP procedures (REGISTER, INVITE/call) are the source of truth.
  2. Counters are derived by counting procedure outcomes; KPIs from counters.
  3. Fault scenarios raise alarms AND degrade the same procedures,
     and emit fault-specific log lines, so everything correlates.

Outputs:
  ims.log        - all nodes merged, time-sorted
  pcscf.log / icscf.log / scscf.log   - Kamailio syslog-style
  pyhss.log      - PyHSS python-logging style (Diameter Cx)
  rtpengine.log  - RTPEngine syslog-style (media, per-call stats + MOS)
  dns.log        - BIND/named query log style
  counters.csv   - per-ROP (15 min) IMS counters
  kpis.csv       - registration SR, CSSR, call drop rate, mean MOS, ...
  alarms.csv     - alarm lifecycle (X.733-style)
  events.csv     - structured per-procedure traces (joinable on trace_id)

Cross-correlation with the core generator:
  --core-alarms path/to/core/alarms.csv   (output of core_synth.py)
      UPF_PFCP_DOWN   -> media path broken: call setups fail, RTPEngine
                         timeouts, active calls drop
      N2_SCTP_FLAP    -> registration/call traffic dip (UEs unreachable)
      MONGODB_DOWN    -> (PyHSS uses its own DB - no effect, on purpose)
  Use the same --days / --seed as the other runs to align timestamps.

Usage:
  python ims_synth.py --days 3 --seed 21 --outdir ./ims \
                      --core-alarms ./core/alarms.csv
"""

import argparse
import csv
import math
import os
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

ROP_MINUTES = 15
ROPS_PER_DAY = 24 * 60 // ROP_MINUTES

MCC, MNC = "999", "70"
IMS_DOMAIN = f"ims.mnc0{MNC}.mcc{MCC}.3gpp.network.org"
HOST = "ims"

PID = {"pcscf": 3021, "icscf": 3045, "scscf": 3067,
       "rtpengine": 2201, "named": 812}


# ----------------------------------------------------------------------------
# Fault / alarm model
# ----------------------------------------------------------------------------
# effects multipliers:
#   reg_fail_x   - SIP registration failure prob multiplier
#   call_fail_x  - call setup (INVITE) failure prob multiplier
#   drop_x       - mid-call drop prob multiplier
#   traffic_x    - scales attempt volume
#   mos_penalty  - subtracted from generated MOS scores

FAULT_TYPES = {
    "PYHSS_DOWN": dict(
        severity="CRITICAL", node="pyhss",
        probable_cause="Communications Subsystem Failure (Diameter Cx)",
        specific_problem="HSS not answering MAR/SAR, registrations failing",
        effects=dict(reg_fail_x=60.0),
        duration_rops=(1, 4),
        per_rop_logs=[
            ("scscf", "ERROR", "cdp [routing.c:280]: Cx MAR timeout, no answer from hss.{dom}", None),
            ("icscf", "ERROR", "cdp [routing.c:280]: Cx UAR timeout, peer hss.{dom} DOWN", None),
        ],
    ),
    "RTPENGINE_DOWN": dict(
        severity="CRITICAL", node="rtpengine",
        probable_cause="Equipment Failure (media relay)",
        specific_problem="RTPEngine not responding on ng control socket",
        effects=dict(call_fail_x=45.0),
        duration_rops=(1, 4),
        per_rop_logs=[
            ("pcscf", "ERROR", "rtpengine [rtpengine.c:2612]: no available proxies, ng socket udp:127.0.0.1:2223 timeout", None),
        ],
    ),
    "DNS_FAILURE": dict(
        severity="MAJOR", node="dns",
        probable_cause="Communications Subsystem Failure (DNS)",
        specific_problem="named not resolving IMS domain, SIP routing failing",
        effects=dict(reg_fail_x=6.0, call_fail_x=8.0),
        duration_rops=(1, 6),
        per_rop_logs=[
            ("dns", "SERVFAIL", "query failed (SERVFAIL) for scscf.{dom}/IN/A", None),
            ("icscf", "ERROR", "tm [t_lookup.c:1451]: DNS resolution failed for scscf.{dom}", None),
        ],
    ),
    "SCSCF_OVERLOAD": dict(
        severity="MAJOR", node="scscf",
        probable_cause="Congestion (SIP transaction load)",
        specific_problem="S-CSCF replying 503 Service Unavailable, tm table full",
        effects=dict(reg_fail_x=7.0, call_fail_x=5.0),
        duration_rops=(2, 8),
        per_rop_logs=[
            ("scscf", "WARNING", "tm [t_funcs.c:110]: high transaction load, replying 503 Retry-After=30", None),
        ],
    ),
    "KAMAILIO_RESTART": dict(
        severity="MINOR", node="pcscf",
        probable_cause="Software Error (process supervision restart)",
        specific_problem="P-CSCF restarted, active dialogs and registrations lost",
        effects=dict(drop_x=10.0, dialog_wipe=True),
        duration_rops=(1, 1),
        per_rop_logs=[
            ("pcscf", "ALERT", "core [main.c:790]: shutting down, active dialogs will be lost", None),
            ("pcscf", "INFO", "core [main.c:2200]: version: kamailio 5.7.4, listening on udp:0.0.0.0:5060", None),
        ],
    ),
    "MEDIA_QOS_DEGRADED": dict(
        severity="MAJOR", node="rtpengine",
        probable_cause="Quality of Service Degraded (RTP packet loss)",
        specific_problem="High RTP packet loss / jitter on media path",
        effects=dict(drop_x=4.0, mos_penalty=1.4),
        duration_rops=(4, 20),
        per_rop_logs=[
            ("rtpengine", "WARNING", "[core] high packet loss detected on media ports, avg loss > 8%", None),
        ],
    ),
    "REGISTRATION_STORM": dict(
        severity="MINOR", node="pcscf",
        probable_cause="Threshold Crossed (registration rate)",
        specific_problem="Re-registration storm, REGISTER rate above threshold",
        effects=dict(reg_traffic_x=3.5),
        duration_rops=(1, 3),
        per_rop_logs=[
            ("pcscf", "WARNING", "pike [ip_tree.c:242]: REGISTER burst detected, rate limiting active", None),
        ],
    ),
}

FAULT_WEIGHTS = {
    "PYHSS_DOWN": 2, "RTPENGINE_DOWN": 2, "DNS_FAILURE": 2,
    "SCSCF_OVERLOAD": 3, "KAMAILIO_RESTART": 3,
    "MEDIA_QOS_DEGRADED": 3, "REGISTRATION_STORM": 2,
}


@dataclass
class ActiveFault:
    fault_type: str
    alarm_id: str
    raised_at: datetime
    remaining_rops: int


# ----------------------------------------------------------------------------
# Generator
# ----------------------------------------------------------------------------

class ImsSynth:
    def __init__(self, days, seed, subscribers, peak_calls, fault_rate,
                 trace_sample_rate, core_alarms_path=None):
        self.rng = random.Random(seed)
        self.days = days
        self.subscribers = subscribers
        self.peak_calls = peak_calls        # call attempts/ROP at daily peak
        self.fault_rate = fault_rate
        self.trace_sample_rate = trace_sample_rate
        self.start = datetime(2026, 7, 6, 0, 0, 0)  # match the other runs

        self.active_faults = {}
        self.imported_windows = []          # (start, end, fault_type)
        if core_alarms_path:
            self._import_core_alarms(core_alarms_path)

        self.log_rows = []                  # (datetime, node, line)
        self.counters_rows = []
        self.kpi_rows = []
        self.alarm_rows = []
        self.event_rows = []
        self.active_regs = subscribers * 0.7
        self.active_calls = 0.0

    # ---------------- core correlation ----------------

    CORE_MAP = {"UPF_PFCP_DOWN": "media", "N2_SCTP_FLAP": "access"}

    def _import_core_alarms(self, path):
        pending = {}
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                ftype = row.get("fault_type", "")
                if ftype not in self.CORE_MAP:
                    continue
                ts = datetime.fromisoformat(row["event_time"])
                aid = row["alarm_id"]
                if row.get("action") == "RAISE":
                    pending[aid] = (ts, ftype)
                elif row.get("action") == "CLEAR" and aid in pending:
                    start, ft = pending.pop(aid)
                    self.imported_windows.append((start, ts, ft))
        for start, ft in pending.values():
            self.imported_windows.append(
                (start, start + timedelta(minutes=ROP_MINUTES), ft))
        print(f"imported {len(self.imported_windows)} core windows "
              f"for IMS correlation")

    def _core_effects(self, ts, eff):
        te = ts + timedelta(minutes=ROP_MINUTES)
        for start, end, ftype in self.imported_windows:
            if start < te and end > ts:
                kind = self.CORE_MAP[ftype]
                if kind == "media":       # UPF down: media path is gone
                    eff["call_fail_x"] *= 25.0
                    eff["drop_x"] *= 15.0
                    eff["core_media_down"] = True
                elif kind == "access":    # RAN/N2 loss: UEs unreachable
                    eff["traffic_x"] *= 0.45
        return eff

    # ---------------- traffic shape ----------------

    def diurnal(self, ts, night=0.15):
        h = ts.hour + ts.minute / 60.0
        shape = 0.5 - 0.5 * math.cos((h - 4) / 24 * 2 * math.pi)
        shape = shape ** 1.4
        return night + (1 - night) * shape

    # ---------------- fault lifecycle ----------------

    def maybe_start_fault(self, ts):
        if self.rng.random() >= self.fault_rate:
            return
        ftype = self.rng.choices(list(FAULT_WEIGHTS),
                                 weights=FAULT_WEIGHTS.values())[0]
        if ftype in self.active_faults:
            return
        spec = FAULT_TYPES[ftype]
        lo, hi = spec["duration_rops"]
        alarm_id = uuid.uuid4().hex[:12]
        self.active_faults[ftype] = ActiveFault(
            ftype, alarm_id, ts, self.rng.randint(lo, hi))
        self.alarm_rows.append(dict(
            alarm_id=alarm_id, fault_type=ftype, node=spec["node"],
            severity=spec["severity"], probable_cause=spec["probable_cause"],
            specific_problem=spec["specific_problem"],
            event_time=ts.isoformat(), action="RAISE"))

    def tick_faults(self, ts_end):
        for ftype in list(self.active_faults):
            f = self.active_faults[ftype]
            f.remaining_rops -= 1
            if f.remaining_rops <= 0:
                spec = FAULT_TYPES[ftype]
                self.alarm_rows.append(dict(
                    alarm_id=f.alarm_id, fault_type=ftype, node=spec["node"],
                    severity="CLEARED",
                    probable_cause=spec["probable_cause"],
                    specific_problem=spec["specific_problem"],
                    event_time=ts_end.isoformat(), action="CLEAR"))
                del self.active_faults[ftype]

    def combined_effects(self, ts):
        eff = dict(reg_fail_x=1.0, call_fail_x=1.0, drop_x=1.0,
                   traffic_x=1.0, reg_traffic_x=1.0, mos_penalty=0.0,
                   dialog_wipe=False)
        for ftype in self.active_faults:
            e = FAULT_TYPES[ftype]["effects"]
            for k in ("reg_fail_x", "call_fail_x", "drop_x",
                      "traffic_x", "reg_traffic_x"):
                eff[k] *= e.get(k, 1.0)
            eff["mos_penalty"] += e.get("mos_penalty", 0.0)
            eff["dialog_wipe"] |= e.get("dialog_wipe", False)
        return self._core_effects(ts, eff)

    # ---------------- log emission ----------------

    def _log(self, t, node, level, msg):
        stamp = t.strftime("%b %e %H:%M:%S")
        if node == "pyhss":
            line = (f"{t.strftime('%Y-%m-%d %H:%M:%S')},"
                    f"{t.microsecond // 1000:03d} [{level}] {msg}")
        elif node == "dns":
            line = (f"{t.strftime('%d-%b-%Y %H:%M:%S')}."
                    f"{t.microsecond // 1000:03d} queries: "
                    f"{'error' if level == 'SERVFAIL' else 'info'}: {msg}")
        elif node == "rtpengine":
            line = f"{stamp} {HOST} rtpengine[{PID['rtpengine']}]: {level}: {msg}"
        else:  # kamailio pcscf/icscf/scscf
            line = (f"{stamp} {HOST} kamailio-{node}[{PID[node]}]: "
                    f"{level}: {msg}")
        self.log_rows.append((t, node, line))

    def _ev(self, t, trace, impu, etype, node, result="OK", detail=""):
        self.event_rows.append(dict(
            timestamp=t.isoformat(timespec="milliseconds"),
            trace_id=trace, impu=impu, node=node,
            event_type=etype, result=result, detail=detail))

    def _rand_user(self):
        n = self.rng.randrange(1, self.subscribers + 1)
        msisdn = f"+{MCC}{MNC}{n:010d}"
        return f"sip:{msisdn}@{IMS_DOMAIN}", msisdn

    def _callid(self):
        return uuid.uuid4().hex[:16] + "@" + IMS_DOMAIN

    # ---------------- one ROP ----------------

    def gen_rop(self, ts):
        eff = self.combined_effects(ts)
        shape = self.diurnal(ts)

        # registrations: re-registration churn of the subscriber base
        reg_lam = (self.subscribers * 0.12) * (0.5 + shape) \
            * eff["traffic_x"] * eff["reg_traffic_x"] \
            * self.rng.uniform(0.9, 1.1)
        reg_att = max(0, int(self.rng.gauss(reg_lam, reg_lam * 0.08)))
        reg_fail_p = min(0.97, 0.006 * eff["reg_fail_x"])
        reg_succ = sum(1 for _ in range(reg_att)
                       if self.rng.random() > reg_fail_p)

        # registered-user pool
        if eff["dialog_wipe"]:
            self.active_regs *= 0.3
        self.active_regs = min(
            self.subscribers,
            self.active_regs * 0.9 + reg_succ * 0.8
            - reg_att * reg_fail_p * 0.5)
        self.active_regs = max(0.0, self.active_regs)

        # calls
        call_lam = self.peak_calls * shape * eff["traffic_x"] \
            * self.rng.uniform(0.9, 1.1)
        call_att = max(0, int(self.rng.gauss(call_lam, call_lam * 0.1)))
        call_fail_p = min(0.98, 0.02 * eff["call_fail_x"])   # network fails
        busy_noanswer_p = 0.14                               # user behaviour
        answered = 0
        net_failed = 0
        for _ in range(call_att):
            if self.rng.random() < call_fail_p:
                net_failed += 1
            elif self.rng.random() > busy_noanswer_p:
                answered += 1
        drop_p = min(0.6, 0.008 * eff["drop_x"])
        dropped = sum(1 for _ in range(answered)
                      if self.rng.random() < drop_p)

        if eff["dialog_wipe"]:
            self.active_calls = 0.0
        self.active_calls = max(
            0.0, self.active_calls * 0.4 + answered * 0.5)

        # MOS for answered calls
        mos_mean = max(1.0, 4.35 - eff["mos_penalty"]
                       - (0.3 if eff.get("core_media_down") else 0.0))
        mos_avg = round(min(4.5, self.rng.gauss(mos_mean, 0.08)), 2)

        counters = dict(
            SIP_RegisterAtt=reg_att, SIP_RegisterSucc=reg_succ,
            SIP_InviteAtt=call_att, SIP_InviteAnswered=answered,
            SIP_InviteNetworkFail=net_failed,
            SIP_CallDropped=dropped,
            IMS_ActiveRegistrations=int(self.active_regs),
            IMS_ActiveCalls=int(self.active_calls),
            RTP_MosAvg=mos_avg,
        )
        self._emit_counters(ts, counters)
        self._emit_kpis(ts, counters)
        self._emit_fault_logs(ts, eff)
        self._emit_sample_traces(ts, reg_att, reg_fail_p,
                                 call_att, call_fail_p, busy_noanswer_p,
                                 drop_p, mos_mean, eff)

    def _emit_counters(self, ts, c):
        self.counters_rows.append(dict(rop_start=ts.isoformat(), **c))

    def _emit_kpis(self, ts, c):
        def ratio(n, d):
            return round(100.0 * n / d, 2) if d else None
        att = c["SIP_InviteAtt"]
        self.kpi_rows.append(dict(
            rop_start=ts.isoformat(),
            registration_sr_pct=ratio(c["SIP_RegisterSucc"],
                                      c["SIP_RegisterAtt"]),
            call_setup_sr_pct=ratio(att - c["SIP_InviteNetworkFail"], att),
            answer_seizure_ratio_pct=ratio(c["SIP_InviteAnswered"], att),
            call_drop_rate_pct=ratio(c["SIP_CallDropped"],
                                     c["SIP_InviteAnswered"]),
            mos_avg=c["RTP_MosAvg"],
            active_registrations=c["IMS_ActiveRegistrations"],
            active_calls=c["IMS_ActiveCalls"],
        ))

    def _emit_fault_logs(self, ts, eff):
        for ftype in self.active_faults:
            for node, level, tmpl, _ in FAULT_TYPES[ftype].get(
                    "per_rop_logs", []):
                t = ts + timedelta(seconds=self.rng.uniform(
                    0, ROP_MINUTES * 60))
                self._log(t, node, level, tmpl.format(dom=IMS_DOMAIN))
        if eff.get("core_media_down"):
            t = ts + timedelta(seconds=self.rng.uniform(0, 120))
            self._log(t, "rtpengine", "WARNING",
                      "[core] media timeout on all open calls, "
                      "no RTP received (upstream GTP-U path down?)")

    # ---------------- sampled traces ----------------

    def _emit_sample_traces(self, ts, reg_att, reg_fail_p,
                            call_att, call_fail_p, busy_p, drop_p,
                            mos_mean, eff):
        # ---- registrations ----
        for _ in range(int(reg_att * self.trace_sample_rate)):
            t = ts + timedelta(seconds=self.rng.uniform(0, ROP_MINUTES * 60))
            impu, msisdn = self._rand_user()
            impi = f"{msisdn.lstrip('+')}@{IMS_DOMAIN}"
            trace = uuid.uuid4().hex[:10]
            cid = self._callid()
            step = timedelta(milliseconds=1)

            self._log(t, "pcscf", "INFO",
                      f"registrar [save.c:412]: REGISTER {impu} "
                      f"Call-ID: {cid} expires=600000")
            self._ev(t, trace, impu, "REGISTER", "pcscf")
            t += step * self.rng.randint(3, 12)
            self._log(t, "icscf", "INFO",
                      f"cdp [routing.c:118]: Cx UAR for {impi}, "
                      f"assigned scscf.{IMS_DOMAIN}")
            t += step * self.rng.randint(3, 12)
            self._log(t, "pyhss", "INFO",
                      f"diameter.py: Multimedia-Auth-Request (MAR) for "
                      f"IMPI {impi}, generating AKA vector")
            t += step * self.rng.randint(5, 20)
            if self.rng.random() < reg_fail_p:
                self._log(t, "scscf", "WARNING",
                          f"registrar [save.c:512]: authentication failed "
                          f"for {impu}, replying 403 Forbidden")
                self._ev(t, trace, impu, "REGISTER", "scscf", "FAIL",
                         "403 Forbidden")
                continue
            self._log(t, "scscf", "INFO",
                      f"registrar [save.c:498]: 401 challenge -> "
                      f"REGISTER w/ auth -> 200 OK for {impu}")
            t += step * self.rng.randint(3, 10)
            self._log(t, "pyhss", "INFO",
                      f"diameter.py: Server-Assignment-Request (SAR) "
                      f"REGISTRATION for {impi}, profile served")
            self._ev(t, trace, impu, "REGISTER", "scscf", "OK", "200 OK")

        # ---- calls ----
        for _ in range(int(call_att * self.trace_sample_rate)):
            t = ts + timedelta(seconds=self.rng.uniform(0, ROP_MINUTES * 60))
            a_impu, _ = self._rand_user()
            b_impu, _ = self._rand_user()
            trace = uuid.uuid4().hex[:10]
            cid = self._callid()
            step = timedelta(milliseconds=1)

            self._log(t, "pcscf", "INFO",
                      f"tm [t_lookup.c:990]: INVITE {a_impu} -> {b_impu} "
                      f"Call-ID: {cid}")
            self._ev(t, trace, a_impu, "INVITE", "pcscf", "OK", b_impu)
            t += step * self.rng.randint(2, 8)
            self._log(t, "dns", "INFO",
                      f"client 127.0.0.1#5060 (scscf.{IMS_DOMAIN}): "
                      f"query: scscf.{IMS_DOMAIN} IN NAPTR +E(0)")
            t += step * self.rng.randint(2, 8)

            if self.rng.random() < call_fail_p:
                if "RTPENGINE_DOWN" in self.active_faults or \
                        eff.get("core_media_down"):
                    self._log(t, "pcscf", "ERROR",
                              f"rtpengine [rtpengine.c:2680]: offer failed "
                              f"Call-ID: {cid}, replying 500")
                    detail = "500 media"
                else:
                    self._log(t, "scscf", "WARNING",
                              f"tm [t_reply.c:1201]: INVITE Call-ID: {cid} "
                              f"failed, 503/timeout downstream")
                    detail = "503"
                self._ev(t, trace, a_impu, "CALL_SETUP", "scscf", "FAIL",
                         detail)
                continue

            self._log(t, "rtpengine", "INFO",
                      f"[{cid}]: Creating new call, offer received, "
                      f"2 media ports allocated")
            t += step * self.rng.randint(20, 60)
            if self.rng.random() < busy_p:
                code = self.rng.choice(["486 Busy Here", "480 No Answer"])
                self._log(t, "scscf", "INFO",
                          f"tm [t_reply.c:900]: Call-ID: {cid} "
                          f"final reply {code}")
                self._log(t + step * 3, "rtpengine", "INFO",
                          f"[{cid}]: Deleting call, no media flowed")
                self._ev(t, trace, a_impu, "CALL_SETUP", "scscf",
                         "NO_ANSWER", code)
                continue

            self._log(t, "scscf", "INFO",
                      f"tm [t_reply.c:900]: Call-ID: {cid} "
                      f"180 Ringing -> 200 OK, dialog confirmed")
            self._ev(t, trace, a_impu, "CALL_ANSWERED", "scscf")

            hold = self.rng.expovariate(1 / 120.0)  # mean 2 min
            dropped = self.rng.random() < drop_p
            t_end = t + timedelta(seconds=hold)
            mos = round(max(1.0, min(4.5,
                        self.rng.gauss(mos_mean, 0.25))), 1)
            pkts = int(hold * 50)
            loss_pct = round(max(0.0, self.rng.gauss(
                (4.4 - mos) * 3.0, 0.5)), 1)
            if dropped:
                self._log(t_end, "rtpengine", "WARNING",
                          f"[{cid}]: media timeout, no RTP for 30s, "
                          f"closing call")
                self._log(t_end + step * 5, "pcscf", "WARNING",
                          f"dialog [dlg_handlers.c:520]: Call-ID: {cid} "
                          f"terminated on media timeout")
                result = "DROPPED"
            else:
                self._log(t_end, "pcscf", "INFO",
                          f"dialog [dlg_handlers.c:490]: BYE Call-ID: {cid}, "
                          f"duration {int(hold)}s")
                result = "COMPLETED"
            self._log(t_end + step * 8, "rtpengine", "INFO",
                      f"[{cid}]: Final stats: {pkts} packets, "
                      f"{loss_pct}% loss, MOS {mos}")
            self._ev(t_end, trace, a_impu, "CALL_END", "rtpengine",
                     result, f"dur={int(hold)}s mos={mos}")

    # ---------------- main loop ----------------

    def run(self):
        n_rops = self.days * ROPS_PER_DAY
        for i in range(n_rops):
            ts = self.start + timedelta(minutes=ROP_MINUTES * i)
            self.maybe_start_fault(ts)
            self.gen_rop(ts)
            self.tick_faults(ts + timedelta(minutes=ROP_MINUTES))
        self.log_rows.sort(key=lambda r: r[0])
        self.event_rows.sort(key=lambda r: r["timestamp"])

    def write(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        path = os.path.join(outdir, "ims.log")
        with open(path, "w") as f:
            for _, _, line in self.log_rows:
                f.write(line + "\n")
        print(f"wrote {path} ({len(self.log_rows)} lines)")

        by_node = {}
        for _, node, line in self.log_rows:
            by_node.setdefault(node, []).append(line)
        for node in sorted(by_node):
            path = os.path.join(outdir, f"{node}.log")
            with open(path, "w") as f:
                f.write("\n".join(by_node[node]) + "\n")
            print(f"wrote {path} ({len(by_node[node])} lines)")

        for name, rows in [("counters.csv", self.counters_rows),
                           ("kpis.csv", self.kpi_rows),
                           ("alarms.csv", self.alarm_rows),
                           ("events.csv", self.event_rows)]:
            path = os.path.join(outdir, name)
            if not rows:
                open(path, "w").close()
                continue
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
            print(f"wrote {path} ({len(rows)} rows)")


def main():
    ap = argparse.ArgumentParser(description="Synthetic IMS generator")
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--seed", type=int, default=21)
    ap.add_argument("--subscribers", type=int, default=5000,
                    help="IMS subscriber base size")
    ap.add_argument("--peak-calls", type=int, default=600,
                    help="call attempts/ROP at daily peak")
    ap.add_argument("--fault-rate", type=float, default=0.02,
                    help="per-ROP probability an IMS fault starts")
    ap.add_argument("--trace-sample-rate", type=float, default=0.02,
                    help="fraction of procedures emitted as full traces")
    ap.add_argument("--core-alarms", default=None,
                    help="alarms.csv from core_synth.py for correlation")
    ap.add_argument("--outdir", default="./ims")
    args = ap.parse_args()

    g = ImsSynth(args.days, args.seed, args.subscribers, args.peak_calls,
                 args.fault_rate, args.trace_sample_rate, args.core_alarms)
    g.run()
    g.write(args.outdir)


if __name__ == "__main__":
    main()
