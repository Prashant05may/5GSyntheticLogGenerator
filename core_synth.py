#!/usr/bin/env python3
"""
Synthetic 5G Core (Open5GS-style) Observability Data Generator
===============================================================
Companion to gnb_synth.py. Same design principles:
  1. Procedures (registration, PDU session establishment) are the source
     of truth. Counters are derived by counting procedure outcomes.
  2. KPIs are computed from counters.
  3. Fault scenarios raise alarms AND degrade procedure success
     probabilities, and additionally emit fault-specific log lines,
     so logs / alarms / KPI degradations are all correlated.

Outputs:
  core.log      - Open5GS-style log lines across NFs (amf, smf, upf, ausf,
                  udm, udr, pcf, nrf, nssf), time-sorted. Sampled INFO
                  traces + all WARN/ERROR lines.
  counters.csv  - per-ROP (15 min) core-level PM counters
  kpis.csv      - per-ROP KPIs (registration SR, auth SR, PDU SR, ...)
  alarms.csv    - alarm lifecycle records (raise/clear, X.733-style)
  events.csv    - sampled per-UE procedure event traces (structured
                  mirror of the log traces, joinable on trace_id)

Cross-correlation with the RAN generator:
  --gnb-alarms path/to/alarms.csv  (output of gnb_synth.py)
      Imports AMF_UNREACHABLE / CELL_DOWN windows from the RAN run and
      mirrors them on the core side (N2 SCTP release logs, traffic dips),
      so a joined RAN+core dataset tells one consistent story.
  Use the same --days / --seed / start date as the gNB run to align.

Usage:
  python core_synth.py --days 3 --seed 42 --outdir ./out_core \
                       --gnb-alarms ./out/alarms.csv
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

MCC, MNC = "999", "70"          # Open5GS defaults
DNN = "internet"

NF_ADDR = {                      # loopback plan mirrors a typical Open5GS lab
    "amf": "127.0.0.5", "smf": "127.0.0.4", "upf": "127.0.0.7",
    "ausf": "127.0.0.11", "udm": "127.0.0.12", "udr": "127.0.0.20",
    "pcf": "127.0.0.13", "nrf": "127.0.0.10", "nssf": "127.0.0.14",
}


# ----------------------------------------------------------------------------
# Fault / alarm model
# ----------------------------------------------------------------------------
# effects multipliers:
#   reg_fail_x   - registration (incl. auth) failure prob multiplier
#   auth_fail_x  - authentication-specific failure prob multiplier
#   pdu_fail_x   - PDU session establishment failure prob multiplier
#   traffic_x    - scales incoming attempt volume (e.g. RAN unreachable)
# per_rop_logs: (nf, level, template, src) emitted every ROP while active

FAULT_TYPES = {
    "UPF_PFCP_DOWN": dict(
        severity="CRITICAL", nf="upf",
        probable_cause="Communications Subsystem Failure (PFCP)",
        specific_problem="UPF not responding to PFCP heartbeat, N4 down",
        effects=dict(pdu_fail_x=80.0),
        duration_rops=(1, 6),
        per_rop_logs=[
            ("smf", "ERROR", "No Heartbeat from UPF [{upf}]:8805", "../lib/pfcp/xact.c:600"),
            ("smf", "WARNING", "PFCP association lost, UPF pool empty for DNN[{dnn}]", "../src/smf/pfcp-path.c:112"),
        ],
    ),
    "MONGODB_DOWN": dict(
        severity="CRITICAL", nf="udr",
        probable_cause="Database Failure (mongod not reachable)",
        specific_problem="UDR lost MongoDB connection, subscription reads fail",
        effects=dict(auth_fail_x=40.0, reg_fail_x=10.0),
        duration_rops=(1, 4),
        per_rop_logs=[
            ("udr", "ERROR", "MongoDB connection refused [mongodb://localhost/open5gs]", "../lib/dbi/ogs-mongoc.c:130"),
            ("udm", "WARNING", "Nudr response error [503 Service Unavailable]", "../src/udm/nudr-handler.c:88"),
        ],
    ),
    "NRF_UNREACHABLE": dict(
        severity="MAJOR", nf="nrf",
        probable_cause="Communications Subsystem Failure (SBI)",
        specific_problem="NF discovery failing, NRF not responding on SBI",
        effects=dict(pdu_fail_x=12.0, reg_fail_x=2.0),
        duration_rops=(1, 4),
        per_rop_logs=[
            ("amf", "WARNING", "Retry NF discovery [NRF {nrf}:7777] connection timeout", "../lib/sbi/client.c:527"),
            ("smf", "ERROR", "Cannot discover PCF via NRF, using fallback", "../src/smf/sbi-path.c:210"),
        ],
    ),
    "AMF_OVERLOAD": dict(
        severity="MAJOR", nf="amf",
        probable_cause="Congestion (SBI/NGAP overload)",
        specific_problem="AMF overload control active, registrations rejected",
        effects=dict(reg_fail_x=8.0),
        duration_rops=(2, 8),
        per_rop_logs=[
            ("amf", "WARNING", "OVERLOAD-START: rejecting non-emergency registrations", "../src/amf/ngap-handler.c:1490"),
        ],
    ),
    "SMF_RESTART": dict(
        severity="MINOR", nf="smf",
        probable_cause="Software Error (process supervision restart)",
        specific_problem="SMF restarted, active PFCP sessions released",
        effects=dict(pdu_fail_x=6.0, session_wipe=True),
        duration_rops=(1, 1),
        per_rop_logs=[
            ("smf", "WARNING", "SMF restart detected, releasing all PFCP sessions", "../src/smf/context.c:95"),
            ("upf", "WARNING", "PFCP association setup request from SMF [{smf}]", "../src/upf/pfcp-sm.c:180"),
        ],
    ),
    "PCF_POLICY_FAILURE": dict(
        severity="MINOR", nf="pcf",
        probable_cause="Configuration or Customisation Error (policy)",
        specific_problem="SM policy association failures for DNN",
        effects=dict(pdu_fail_x=3.0),
        duration_rops=(4, 24),
        per_rop_logs=[
            ("pcf", "WARNING", "SM policy cannot be created [DNN:{dnn}] no matching policy set", "../src/pcf/npcf-handler.c:340"),
        ],
    ),
    "SLICE_MISCONFIG": dict(
        severity="MINOR", nf="nssf",
        probable_cause="Configuration or Customisation Error (S-NSSAI)",
        specific_problem="Requested S-NSSAI not served, slice selection fallback",
        effects=dict(reg_fail_x=1.6),
        duration_rops=(8, 48),
        per_rop_logs=[
            ("nssf", "WARNING", "No matching NSI for S-NSSAI[SST:1 SD:0x000001], default applied", "../src/nssf/nnssf-handler.c:77"),
        ],
    ),
    "N2_SCTP_FLAP": dict(
        severity="MAJOR", nf="amf",
        probable_cause="Communications Protocol Error (N2 / SCTP)",
        specific_problem="NG interface to gNB flapping, RAN signalling lost",
        effects=dict(traffic_x=0.35),
        duration_rops=(1, 4),
        per_rop_logs=[
            ("amf", "WARNING", "gNB-N2[{gnb_ip}] connection refused, SCTP shutdown", "../src/amf/ngap-sctp.c:113"),
            ("amf", "INFO", "gNB-N2 removed, ran_ue context released", "../src/amf/context.c:1120"),
        ],
    ),
}

FAULT_WEIGHTS = {
    "UPF_PFCP_DOWN": 2, "MONGODB_DOWN": 1, "NRF_UNREACHABLE": 2,
    "AMF_OVERLOAD": 3, "SMF_RESTART": 3, "PCF_POLICY_FAILURE": 2,
    "SLICE_MISCONFIG": 2, "N2_SCTP_FLAP": 3,
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

class CoreSynth:
    def __init__(self, days, seed, peak_reg, fault_rate, trace_sample_rate,
                 gnb_alarms_path=None):
        self.rng = random.Random(seed)
        self.days = days
        self.peak_reg = peak_reg            # registrations/ROP at daily peak
        self.fault_rate = fault_rate        # per-ROP fault start probability
        self.trace_sample_rate = trace_sample_rate
        self.start = datetime(2026, 7, 6, 0, 0, 0)  # match gnb_synth.py

        self.active_faults = {}             # fault_type -> ActiveFault
        self.imported_windows = []          # (start, end, gnb_id) from RAN run
        if gnb_alarms_path:
            self._import_gnb_alarms(gnb_alarms_path)

        self.log_rows = []                  # (datetime, nf, str line)
        self.counters_rows = []
        self.kpi_rows = []
        self.alarm_rows = []
        self.event_rows = []
        self.active_sessions = 0.0          # smoothed PDU session count

    # ---------------- RAN correlation ----------------

    def _import_gnb_alarms(self, path):
        """Mirror RAN-side AMF_UNREACHABLE / CELL_DOWN windows on the core."""
        # gnb_synth.py emits RAISE and CLEAR as separate rows sharing alarm_id
        pending = {}   # alarm_id -> (start, gnb_id, fault_type)
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                ftype = row.get("fault_type", "")
                if ftype not in ("AMF_UNREACHABLE", "CELL_DOWN"):
                    continue
                ts = datetime.fromisoformat(row["timestamp"])
                aid = row["alarm_id"]
                ntype = row.get("notification_type", "")
                if "RAISED" in ntype:
                    pending[aid] = (ts, row.get("gnb_id", "gnb-unknown"), ftype)
                elif "CLEARED" in ntype and aid in pending:
                    start, gnb_id, ft = pending.pop(aid)
                    self.imported_windows.append((start, ts, gnb_id, ft))
        # never-cleared alarms: assume one ROP
        for start, gnb_id, ft in pending.values():
            self.imported_windows.append(
                (start, start + timedelta(minutes=ROP_MINUTES), gnb_id, ft))
        print(f"imported {len(self.imported_windows)} RAN windows "
              f"for N2 correlation")

    def _ran_window_active(self, ts):
        te = ts + timedelta(minutes=ROP_MINUTES)
        for start, end, gnb_id, ftype in self.imported_windows:
            if start < te and end > ts:
                return gnb_id, ftype
        return None

    # ---------------- traffic shape ----------------

    def diurnal(self, ts, night=0.18):
        h = ts.hour + ts.minute / 60.0
        # same flavour as the gNB generator: busy evening, quiet 03:00-05:00
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
            alarm_id=alarm_id, fault_type=ftype, nf=spec["nf"],
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
                    alarm_id=f.alarm_id, fault_type=ftype, nf=spec["nf"],
                    severity="CLEARED",
                    probable_cause=spec["probable_cause"],
                    specific_problem=spec["specific_problem"],
                    event_time=ts_end.isoformat(), action="CLEAR"))
                del self.active_faults[ftype]

    def combined_effects(self, ts):
        eff = dict(reg_fail_x=1.0, auth_fail_x=1.0, pdu_fail_x=1.0,
                   traffic_x=1.0, session_wipe=False)
        for ftype in self.active_faults:
            e = FAULT_TYPES[ftype]["effects"]
            for k in ("reg_fail_x", "auth_fail_x", "pdu_fail_x", "traffic_x"):
                eff[k] *= e.get(k, 1.0)
            eff["session_wipe"] |= e.get("session_wipe", False)
        ran = self._ran_window_active(ts)
        if ran:
            eff["traffic_x"] *= 0.6           # part of the RAN is dark
            eff["ran_window"] = ran
        return eff

    # ---------------- log emission ----------------

    def _log(self, t, nf, level, msg, src):
        line = (f"{t.strftime('%m/%d %H:%M:%S')}."
                f"{t.microsecond // 1000:03d}: [{nf}] {level}: {msg} ({src})")
        self.log_rows.append((t, nf, line))

    def _ev(self, t, trace, supi, etype, nf, result="OK", detail=""):
        self.event_rows.append(dict(
            timestamp=t.isoformat(timespec="milliseconds"),
            trace_id=trace, supi=supi, nf=nf,
            event_type=etype, result=result, detail=detail))

    def _rand_supi(self):
        return f"imsi-{MCC}{MNC}{self.rng.randrange(0, 10**10):010d}"

    def _rand_ue_ip(self):
        return f"10.45.0.{self.rng.randrange(2, 255)}"

    # ---------------- one ROP ----------------

    def gen_rop(self, ts):
        eff = self.combined_effects(ts)
        shape = self.diurnal(ts)
        lam = self.peak_reg * shape * eff["traffic_x"] * \
            self.rng.uniform(0.9, 1.1)

        reg_att = max(0, int(self.rng.gauss(lam, lam * 0.08)))

        # base failure probabilities, degraded by active faults
        auth_fail_p = min(0.95, 0.003 * eff["auth_fail_x"])
        reg_fail_p = min(0.95, 0.004 * eff["reg_fail_x"])
        pdu_fail_p = min(0.98, 0.005 * eff["pdu_fail_x"])

        auth_att = reg_att
        auth_succ = sum(1 for _ in range(auth_att)
                        if self.rng.random() > auth_fail_p)
        reg_succ = sum(1 for _ in range(auth_succ)
                       if self.rng.random() > reg_fail_p)

        pdu_att = int(reg_succ * self.rng.uniform(0.95, 1.0))
        pdu_succ = sum(1 for _ in range(pdu_att)
                       if self.rng.random() > pdu_fail_p)

        # session pool: arrivals minus expirations (mean hold ~ 2 ROPs)
        if eff["session_wipe"]:
            self.active_sessions = 0.0
            self._log(ts + timedelta(seconds=self.rng.uniform(0, 60)),
                      "smf", "WARNING",
                      "Removed all sessions due to restart", "../src/smf/context.c:101")
        self.active_sessions = max(
            0.0, self.active_sessions * 0.6 + pdu_succ * 0.9)

        # paging / dereg follow traffic
        paging_att = int(reg_succ * self.rng.uniform(0.10, 0.20))
        dereg = int(reg_succ * self.rng.uniform(0.85, 1.0))

        counters = dict(
            AMF_RegInitAtt=reg_att, AMF_RegInitSucc=reg_succ,
            AUSF_AuthAtt=auth_att, AUSF_AuthSucc=auth_succ,
            SMF_PduSesCreationAtt=pdu_att, SMF_PduSesCreationSucc=pdu_succ,
            UPF_ActiveSessions=int(self.active_sessions),
            AMF_PagingAtt=paging_att, AMF_DeregTotal=dereg,
            AMF_ActiveFaults=len(self.active_faults),
        )
        self._emit_counters(ts, counters)
        self._emit_kpis(ts, counters)
        self._emit_fault_logs(ts, eff)
        self._emit_sample_traces(ts, reg_att, auth_fail_p, reg_fail_p,
                                 pdu_fail_p)

    def _emit_counters(self, ts, c):
        self.counters_rows.append(dict(rop_start=ts.isoformat(), **c))

    def _emit_kpis(self, ts, c):
        def ratio(n, d):
            return round(100.0 * n / d, 2) if d else None
        self.kpi_rows.append(dict(
            rop_start=ts.isoformat(),
            registration_sr_pct=ratio(c["AMF_RegInitSucc"], c["AMF_RegInitAtt"]),
            auth_sr_pct=ratio(c["AUSF_AuthSucc"], c["AUSF_AuthAtt"]),
            pdu_session_creation_sr_pct=ratio(c["SMF_PduSesCreationSucc"],
                                              c["SMF_PduSesCreationAtt"]),
            active_pdu_sessions=c["UPF_ActiveSessions"],
            registration_attempts=c["AMF_RegInitAtt"],
        ))

    def _emit_fault_logs(self, ts, eff):
        ctx = dict(dnn=DNN, upf=NF_ADDR["upf"], smf=NF_ADDR["smf"],
                   nrf=NF_ADDR["nrf"], gnb_ip="127.0.0.100")
        for ftype in self.active_faults:
            for nf, level, tmpl, src in FAULT_TYPES[ftype].get("per_rop_logs", []):
                t = ts + timedelta(seconds=self.rng.uniform(0, ROP_MINUTES * 60))
                self._log(t, nf, level, tmpl.format(**ctx), src)
        ran = eff.get("ran_window")
        if ran:
            gnb_id, ftype = ran
            t = ts + timedelta(seconds=self.rng.uniform(0, 120))
            if ftype == "AMF_UNREACHABLE":
                self._log(t, "amf", "WARNING",
                          f"gNB-N2[{gnb_id}] SCTP association lost, "
                          f"releasing ran_ue contexts", "../src/amf/ngap-sctp.c:113")
            else:  # CELL_DOWN
                self._log(t, "amf", "INFO",
                          f"NG Setup update from {gnb_id}: served cell removed",
                          "../src/amf/ngap-handler.c:250")

    # ---------------- sampled per-UE traces ----------------

    def _emit_sample_traces(self, ts, reg_att, auth_fail_p, reg_fail_p,
                            pdu_fail_p):
        n = int(reg_att * self.trace_sample_rate)
        for _ in range(n):
            t = ts + timedelta(seconds=self.rng.uniform(0, ROP_MINUTES * 60))
            supi = self._rand_supi()
            suci = supi.replace(f"imsi-{MCC}{MNC}",
                                f"suci-0-{MCC}-{MNC}-0000-0-0-")
            trace = uuid.uuid4().hex[:10]
            step = timedelta(milliseconds=1)

            self._log(t, "amf", "INFO",
                      f"InitialUEMessage [{suci}] Registration request",
                      "../src/amf/ngap-handler.c:401")
            self._ev(t, trace, supi, "REGISTRATION_REQUEST", "amf")

            t += step * self.rng.randint(8, 30)
            if self.rng.random() < auth_fail_p:
                self._log(t, "ausf", "WARNING",
                          f"[{suci}] Authentication failure "
                          f"(Cause: Synch failure / MAC failure)",
                          "../src/ausf/nudm-handler.c:154")
                self._log(t + step * 5, "amf", "WARNING",
                          f"[{suci}] Registration reject "
                          f"[5GMM Cause: Illegal UE]",
                          "../src/amf/gmm-handler.c:230")
                self._ev(t, trace, supi, "AUTHENTICATION", "ausf", "FAIL")
                continue
            self._log(t, "ausf", "INFO",
                      f"[{suci}] Authentication succeeded",
                      "../src/ausf/nudm-handler.c:198")
            self._ev(t, trace, supi, "AUTHENTICATION", "ausf")

            t += step * self.rng.randint(10, 40)
            if self.rng.random() < reg_fail_p:
                self._log(t, "udm", "WARNING",
                          f"[{supi}] Cannot find SDM subscription data",
                          "../src/udm/nudr-handler.c:301")
                self._log(t + step * 5, "amf", "WARNING",
                          f"[{supi}] Registration reject",
                          "../src/amf/gmm-handler.c:230")
                self._ev(t, trace, supi, "REGISTRATION", "amf", "FAIL",
                         "subscription data")
                continue
            self._log(t, "amf", "INFO",
                      f"[{supi}] Registration complete",
                      "../src/amf/gmm-sm.c:1050")
            self._ev(t, trace, supi, "REGISTRATION", "amf")

            # PDU session establishment
            t += step * self.rng.randint(50, 200)
            if self.rng.random() < pdu_fail_p:
                self._log(t, "smf", "ERROR",
                          f"[{supi}] PFCP Session Establishment failed "
                          f"[DNN:{DNN}]", "../src/smf/pfcp-path.c:412")
                self._log(t + step * 8, "amf", "WARNING",
                          f"[{supi}] PDU Session Establishment reject "
                          f"[PSI:1 Cause: Network failure]",
                          "../src/amf/nsmf-handler.c:520")
                self._ev(t, trace, supi, "PDU_SESSION", "smf", "FAIL")
                continue
            ue_ip = self._rand_ue_ip()
            self._log(t, "smf", "INFO",
                      f"UE SUPI[{supi}] DNN[{DNN}] IPv4[{ue_ip}] IPv6[]",
                      "../src/smf/npcf-handler.c:526")
            self._log(t + step * 3, "upf", "INFO",
                      f"UPF Session established [SEID:{self.rng.randrange(1, 10**6)}] "
                      f"UE F-SEID / APN[{DNN}] PDN-Type[1] IPv4[{ue_ip}]",
                      "../src/upf/pfcp-sm.c:290")
            self._ev(t, trace, supi, "PDU_SESSION", "smf", "OK", ue_ip)

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
        log_path = os.path.join(outdir, "core.log")
        with open(log_path, "w") as f:
            for _, _, line in self.log_rows:
                f.write(line + "\n")
        print(f"wrote {log_path} ({len(self.log_rows)} lines)")

        # per-NF log files, like /var/log/open5gs/<nf>.log
        by_nf = {}
        for _, nf, line in self.log_rows:
            by_nf.setdefault(nf, []).append(line)
        for nf in sorted(by_nf):
            path = os.path.join(outdir, f"{nf}.log")
            with open(path, "w") as f:
                f.write("\n".join(by_nf[nf]) + "\n")
            print(f"wrote {path} ({len(by_nf[nf])} lines)")
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
    ap = argparse.ArgumentParser(description="Synthetic 5G core generator")
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--peak-registrations", type=int, default=2500,
                    help="registration attempts/ROP at daily peak (whole core)")
    ap.add_argument("--fault-rate", type=float, default=0.01,
                    help="per-ROP probability a core fault starts")
    ap.add_argument("--trace-sample-rate", type=float, default=0.01,
                    help="fraction of registrations emitted as full traces")
    ap.add_argument("--gnb-alarms", default=None,
                    help="alarms.csv from gnb_synth.py for N2 correlation")
    ap.add_argument("--outdir", default="./out_core")
    args = ap.parse_args()

    g = CoreSynth(args.days, args.seed, args.peak_registrations,
                  args.fault_rate, args.trace_sample_rate, args.gnb_alarms)
    g.run()
    g.write(args.outdir)


if __name__ == "__main__":
    main()
