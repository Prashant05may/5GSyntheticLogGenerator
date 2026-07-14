#!/usr/bin/env python3
"""
Synthetic gNodeB Observability Data Generator
=============================================
Generates causally-consistent Events -> PM Counters -> KPIs -> Alarms
for a configurable set of NR cells over a configurable time window.

Design principles:
  1. Events are the source of truth. Counters are derived by counting events.
  2. KPIs are computed from counters using standard 3GPP-style formulas.
  3. Fault scenarios raise alarms AND degrade the related event probabilities,
     so alarms and KPI degradations are correlated (like a real network).

Outputs (CSV):
  counters.csv  - per-cell, per-ROP (15 min) PM counters (TS 28.552-style names)
  kpis.csv      - per-cell, per-ROP KPIs (accessibility, retainability, mobility,
                  integrity, availability)
  alarms.csv    - alarm lifecycle records (raise/clear, X.733-style severity)
  events.csv    - sampled per-UE signalling event traces (subset, for realism
                  without huge files)

Usage:
  python gnb_synth.py --days 3 --cells 6 --seed 42 --outdir ./out
"""

import argparse
import csv
import math
import os
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

ROP_MINUTES = 15
ROPS_PER_DAY = 24 * 60 // ROP_MINUTES


# ----------------------------------------------------------------------------
# Cell model
# ----------------------------------------------------------------------------

CELL_PROFILES = {
    #                base UE arrivals/ROP at peak, RRC succ prob, HO succ prob,
    #                drop prob, night factor
    "dense_urban":  dict(peak_arrivals=900, rrc_p=0.995, ho_p=0.985,
                         drop_p=0.004, night=0.15),
    "urban":        dict(peak_arrivals=550, rrc_p=0.993, ho_p=0.982,
                         drop_p=0.005, night=0.20),
    "suburban":     dict(peak_arrivals=300, rrc_p=0.991, ho_p=0.980,
                         drop_p=0.006, night=0.25),
    "rural":        dict(peak_arrivals=90,  rrc_p=0.988, ho_p=0.972,
                         drop_p=0.008, night=0.35),
    "degraded":     dict(peak_arrivals=400, rrc_p=0.960, ho_p=0.930,
                         drop_p=0.020, night=0.20),
}


@dataclass
class Cell:
    cell_id: str
    gnb_id: str
    profile: str
    # per-cell persistent personality jitter
    traffic_scale: float = 1.0
    quality_offset: float = 0.0   # shifts success probs slightly
    band: str = "n78"
    bw_mhz: int = 100

    def params(self):
        p = dict(CELL_PROFILES[self.profile])
        p["peak_arrivals"] = p["peak_arrivals"] * self.traffic_scale
        p["rrc_p"] = min(0.9995, p["rrc_p"] + self.quality_offset)
        p["ho_p"] = min(0.999, p["ho_p"] + self.quality_offset)
        p["drop_p"] = max(0.001, p["drop_p"] - self.quality_offset)
        return p


# ----------------------------------------------------------------------------
# Fault / alarm model
# ----------------------------------------------------------------------------

# Each fault type: alarm metadata + multiplicative effects on event probabilities
FAULT_TYPES = {
    "SYNC_LOSS": dict(
        severity="MAJOR",
        probable_cause="Loss of Synchronisation (GNSS holdover)",
        specific_problem="gNB sync source degraded, TDD timing drifting",
        effects=dict(ho_fail_x=8.0, drop_x=5.0, rrc_fail_x=2.0),
        duration_rops=(4, 16),
    ),
    "CONGESTION": dict(
        severity="MINOR",
        probable_cause="Threshold Crossed (PRB utilisation)",
        specific_problem="High PRB utilisation, admission control active",
        effects=dict(rrc_fail_x=4.0, thp_x=0.45, traffic_x=1.35),
        duration_rops=(2, 8),
    ),
    "CELL_DOWN": dict(
        severity="CRITICAL",
        probable_cause="Equipment Failure (baseband processing)",
        specific_problem="NR cell out of service",
        effects=dict(outage=True),
        duration_rops=(1, 6),
    ),
    "RF_VSWR": dict(
        severity="MAJOR",
        probable_cause="Transmitter Antenna VSWR out of range",
        specific_problem="Feeder/antenna mismatch, TX power reduced",
        effects=dict(drop_x=3.0, ho_fail_x=3.0, thp_x=0.7),
        duration_rops=(8, 40),
    ),
    "HIGH_TEMP": dict(
        severity="WARNING",
        probable_cause="Temperature Unacceptable",
        specific_problem="Radio unit temperature approaching shutdown threshold",
        effects=dict(),   # warning only, no KPI impact yet
        duration_rops=(3, 12),
    ),
    "UL_INTERFERENCE": dict(
        severity="MAJOR",
        probable_cause="Receiver Failure (external interference / PIM)",
        specific_problem="UL RSSI elevated, RACH and UL decoding degraded",
        effects=dict(rrc_fail_x=3.5, ul_thp_x=0.35, drop_x=2.0),
        duration_rops=(6, 32),
    ),
    "TRANSPORT_DEGRADED": dict(
        severity="MAJOR",
        probable_cause="Communications Subsystem Failure (backhaul)",
        specific_problem="NG-U packet loss / microwave link fading",
        effects=dict(drop_x=4.0, thp_x=0.5, ul_thp_x=0.5, pdu_fail_x=3.0),
        duration_rops=(2, 12),
    ),
    "AMF_UNREACHABLE": dict(
        severity="CRITICAL",
        probable_cause="Communications Protocol Error (NG-C / SCTP down)",
        specific_problem="NG interface to AMF lost, registrations rejected",
        effects=dict(pdu_fail_x=60.0, rrc_fail_x=1.5),
        duration_rops=(1, 4),
    ),
    "SW_PROCESS_RESTART": dict(
        severity="MINOR",
        probable_cause="Software Error (process supervision restart)",
        specific_problem="Cell service interrupted by DU process restart",
        effects=dict(outage=True),
        duration_rops=(1, 1),
    ),
    "NEIGHBOR_MISSING": dict(
        severity="MINOR",
        probable_cause="Configuration or Customisation Error (ANR)",
        specific_problem="Missing/incorrect neighbour relation, HO to wrong PCI",
        effects=dict(ho_fail_x=6.0, drop_x=1.8),
        duration_rops=(12, 96),
    ),
    "SLEEPING_CELL": dict(
        severity="MAJOR",
        probable_cause="(none raised - silent failure)",
        specific_problem="Cell reports in-service but serves no traffic",
        effects=dict(traffic_x=0.03, thp_x=0.2),
        duration_rops=(4, 24),
        silent=True,   # NO alarm emitted - detectable only from KPIs
    ),
}

# relative likelihood of each fault type when a fault starts
FAULT_WEIGHTS = {
    "SYNC_LOSS": 3, "CONGESTION": 5, "CELL_DOWN": 1, "RF_VSWR": 2,
    "HIGH_TEMP": 4, "UL_INTERFERENCE": 3, "TRANSPORT_DEGRADED": 3,
    "AMF_UNREACHABLE": 1, "SW_PROCESS_RESTART": 2, "NEIGHBOR_MISSING": 2,
    "SLEEPING_CELL": 1,
}


@dataclass
class ActiveFault:
    fault_type: str
    cell_id: str
    alarm_id: str
    raised_at: datetime
    remaining_rops: int


# ----------------------------------------------------------------------------
# Generator
# ----------------------------------------------------------------------------

class GnbSynth:
    def __init__(self, n_cells, days, seed, fault_rate, event_sample_rate):
        self.rng = random.Random(seed)
        self.days = days
        self.fault_rate = fault_rate           # per-cell per-ROP fault start prob
        self.event_sample_rate = event_sample_rate
        self.start = datetime(2026, 7, 6, 0, 0, 0)  # a Monday
        self.cells = self._make_cells(n_cells)
        self.active_faults = {}                # cell_id -> ActiveFault
        self.counters_rows = []
        self.kpi_rows = []
        self.alarm_rows = []
        self.event_rows = []

    def _make_cells(self, n):
        profiles = list(CELL_PROFILES.keys())
        cells = []
        for i in range(n):
            # guarantee at least one degraded cell if we have >= 4 cells
            if i == n - 1 and n >= 4:
                prof = "degraded"
            else:
                prof = self.rng.choice(profiles[:-1])
            cells.append(Cell(
                cell_id=f"NRCell-{i+1:03d}",
                gnb_id=f"gNB-{(i // 3) + 1:03d}",
                profile=prof,
                traffic_scale=self.rng.uniform(0.8, 1.2),
                quality_offset=self.rng.uniform(-0.002, 0.002),
            ))
        return cells

    # ---------------- diurnal traffic ----------------

    def diurnal(self, ts, night_floor):
        """Two-peak weekday profile (midday + evening), damped weekends."""
        h = ts.hour + ts.minute / 60.0
        midday = math.exp(-((h - 12.0) ** 2) / (2 * 3.0 ** 2))
        evening = math.exp(-((h - 20.0) ** 2) / (2 * 2.0 ** 2))
        shape = night_floor + (1 - night_floor) * min(1.0, 0.85 * midday + 0.95 * evening)
        if ts.weekday() >= 5:  # weekend
            shape *= 0.75
        return shape

    # ---------------- fault lifecycle ----------------

    def maybe_start_fault(self, cell, ts):
        if cell.cell_id in self.active_faults:
            return
        if self.rng.random() < self.fault_rate:
            types = list(FAULT_TYPES.keys())
            ftype = self.rng.choices(
                types, weights=[FAULT_WEIGHTS[t] for t in types], k=1)[0]
            spec = FAULT_TYPES[ftype]
            dur = self.rng.randint(*spec["duration_rops"])
            alarm_id = uuid.uuid4().hex[:12]
            self.active_faults[cell.cell_id] = ActiveFault(
                ftype, cell.cell_id, alarm_id, ts, dur)
            if spec.get("silent"):
                return  # sleeping cell: KPI impact but no alarm
            self.alarm_rows.append(dict(
                alarm_id=alarm_id, timestamp=ts.isoformat(),
                gnb_id=cell.gnb_id, cell_id=cell.cell_id,
                notification_type="ALARM_RAISED",
                fault_type=ftype, severity=spec["severity"],
                probable_cause=spec["probable_cause"],
                specific_problem=spec["specific_problem"],
            ))

    def tick_fault(self, cell, ts_end):
        f = self.active_faults.get(cell.cell_id)
        if not f:
            return None
        f.remaining_rops -= 1
        if f.remaining_rops <= 0:
            spec = FAULT_TYPES[f.fault_type]
            if not spec.get("silent"):
                self.alarm_rows.append(dict(
                alarm_id=f.alarm_id, timestamp=ts_end.isoformat(),
                gnb_id=cell.gnb_id, cell_id=cell.cell_id,
                notification_type="ALARM_CLEARED",
                fault_type=f.fault_type, severity="CLEARED",
                probable_cause=spec["probable_cause"],
                specific_problem=spec["specific_problem"],
            ))
            del self.active_faults[cell.cell_id]
        return f

    # ---------------- one ROP for one cell ----------------

    def gen_rop(self, cell, ts):
        p = cell.params()
        fault = self.active_faults.get(cell.cell_id)
        eff = FAULT_TYPES[fault.fault_type]["effects"] if fault else {}

        outage = eff.get("outage", False)
        # availability: seconds in service this ROP
        rop_secs = ROP_MINUTES * 60
        if outage:
            unavail_secs = rop_secs
        else:
            unavail_secs = 0

        shape = self.diurnal(ts, p["night"])
        lam = p["peak_arrivals"] * shape * eff.get("traffic_x", 1.0)
        lam *= self.rng.uniform(0.9, 1.1)  # ROP-level noise

        if outage:
            rrc_att = max(0, int(self.rng.gauss(lam * 0.3, lam * 0.05)))
            rrc_succ = 0
            counters = self._empty_counters(rrc_att)
        else:
            rrc_att = max(0, int(self.rng.gauss(lam, lam * 0.08)))
            rrc_fail_p = min(0.5, (1 - p["rrc_p"]) * eff.get("rrc_fail_x", 1.0))
            rrc_succ = sum(1 for _ in range(rrc_att)
                           if self.rng.random() > rrc_fail_p)

            # PDU sessions: most successful RRC connections establish one
            pdu_att = int(rrc_succ * self.rng.uniform(0.95, 1.0))
            pdu_fail_p = min(0.98, (rrc_fail_p * 0.6 + 0.002)
                             * eff.get("pdu_fail_x", 1.0))
            pdu_succ = sum(1 for _ in range(pdu_att)
                           if self.rng.random() > pdu_fail_p)

            # handovers scale with traffic
            ho_att = max(0, int(rrc_succ * self.rng.uniform(0.25, 0.45)))
            ho_fail_p = min(0.6, (1 - p["ho_p"]) * eff.get("ho_fail_x", 1.0))
            ho_succ = sum(1 for _ in range(ho_att)
                          if self.rng.random() > ho_fail_p)

            # releases: normal + abnormal (drops)
            rel_total = pdu_succ
            drop_p = min(0.4, p["drop_p"] * eff.get("drop_x", 1.0))
            rel_abnormal = sum(1 for _ in range(rel_total)
                               if self.rng.random() < drop_p)

            # load & integrity
            prb_util = min(99.0, 12 + 80 * shape * eff.get("traffic_x", 1.0)
                           * self.rng.uniform(0.85, 1.15))
            thp_dl = max(5.0, (350 - 2.6 * prb_util)
                         * eff.get("thp_x", 1.0)
                         * self.rng.uniform(0.9, 1.1))
            thp_ul = (thp_dl * self.rng.uniform(0.10, 0.18)
                      * eff.get("ul_thp_x", 1.0))
            conn_ue_avg = lam * self.rng.uniform(0.15, 0.25)

            counters = dict(
                RRC_ConnEstabAtt=rrc_att, RRC_ConnEstabSucc=rrc_succ,
                PDU_SesEstabAtt=pdu_att, PDU_SesEstabSucc=pdu_succ,
                MM_HoExeAtt=ho_att, MM_HoExeSucc=ho_succ,
                DRB_RelActNbr=rel_total, DRB_RelActAbnormal=rel_abnormal,
                RRU_PrbTotDlUsedPct=round(prb_util, 1),
                DRB_UEThpDl_Mbps=round(thp_dl, 1),
                DRB_UEThpUl_Mbps=round(thp_ul, 1),
                RRC_ConnMean=round(conn_ue_avg, 1),
            )

        counters["Cell_UnavailSecs"] = unavail_secs
        self._emit_counters(cell, ts, counters)
        self._emit_kpis(cell, ts, counters, rop_secs)
        self._emit_sample_events(cell, ts, counters)

    def _empty_counters(self, rrc_att):
        return dict(
            RRC_ConnEstabAtt=rrc_att, RRC_ConnEstabSucc=0,
            PDU_SesEstabAtt=0, PDU_SesEstabSucc=0,
            MM_HoExeAtt=0, MM_HoExeSucc=0,
            DRB_RelActNbr=0, DRB_RelActAbnormal=0,
            RRU_PrbTotDlUsedPct=0.0, DRB_UEThpDl_Mbps=0.0,
            DRB_UEThpUl_Mbps=0.0, RRC_ConnMean=0.0,
        )

    def _emit_counters(self, cell, ts, c):
        row = dict(rop_start=ts.isoformat(), gnb_id=cell.gnb_id,
                   cell_id=cell.cell_id, profile=cell.profile, **c)
        self.counters_rows.append(row)

    def _emit_kpis(self, cell, ts, c, rop_secs):
        def ratio(n, d):
            return round(100.0 * n / d, 2) if d else None
        avail = round(100.0 * (rop_secs - c["Cell_UnavailSecs"]) / rop_secs, 2)
        self.kpi_rows.append(dict(
            rop_start=ts.isoformat(), gnb_id=cell.gnb_id, cell_id=cell.cell_id,
            rrc_setup_sr_pct=ratio(c["RRC_ConnEstabSucc"], c["RRC_ConnEstabAtt"]),
            pdu_session_estab_sr_pct=ratio(c["PDU_SesEstabSucc"], c["PDU_SesEstabAtt"]),
            ho_success_rate_pct=ratio(c["MM_HoExeSucc"], c["MM_HoExeAtt"]),
            session_drop_rate_pct=ratio(c["DRB_RelActAbnormal"], c["DRB_RelActNbr"]),
            dl_user_thp_mbps=c["DRB_UEThpDl_Mbps"],
            ul_user_thp_mbps=c["DRB_UEThpUl_Mbps"],
            prb_util_dl_pct=c["RRU_PrbTotDlUsedPct"],
            avg_connected_ues=c["RRC_ConnMean"],
            cell_availability_pct=avail,
        ))

    def _emit_sample_events(self, cell, ts, c):
        """Emit a sampled subset of per-UE signalling traces."""
        n_traces = int(c["RRC_ConnEstabAtt"] * self.event_sample_rate)
        fail_p = 0.0
        if c["RRC_ConnEstabAtt"]:
            fail_p = 1 - c["RRC_ConnEstabSucc"] / c["RRC_ConnEstabAtt"]
        for _ in range(n_traces):
            t = ts + timedelta(seconds=self.rng.uniform(0, ROP_MINUTES * 60))
            ue = f"UE-{self.rng.randrange(1, 10**6):06d}"
            trace = uuid.uuid4().hex[:10]
            self._ev(t, cell, ue, trace, "RRC_SETUP_REQUEST")
            if self.rng.random() < fail_p:
                self._ev(t + timedelta(milliseconds=60), cell, ue, trace,
                         "RRC_SETUP_FAILURE")
                continue
            self._ev(t + timedelta(milliseconds=45), cell, ue, trace,
                     "RRC_SETUP_COMPLETE")
            self._ev(t + timedelta(milliseconds=180), cell, ue, trace,
                     "PDU_SESSION_ESTABLISHED")
            hold = self.rng.expovariate(1 / 90.0)  # session seconds
            if self.rng.random() < 0.35:
                self._ev(t + timedelta(seconds=hold * 0.5), cell, ue, trace,
                         "HANDOVER_EXECUTION")
            drop = (self.rng.random() <
                    (c["DRB_RelActAbnormal"] / c["DRB_RelActNbr"]
                     if c["DRB_RelActNbr"] else 0))
            self._ev(t + timedelta(seconds=hold), cell, ue, trace,
                     "ABNORMAL_RELEASE" if drop else "NORMAL_RELEASE")

    def _ev(self, t, cell, ue, trace, etype):
        self.event_rows.append(dict(
            timestamp=t.isoformat(timespec="milliseconds"),
            gnb_id=cell.gnb_id, cell_id=cell.cell_id,
            trace_id=trace, ue_id=ue, event_type=etype))

    # ---------------- main loop ----------------

    def run(self):
        n_rops = self.days * ROPS_PER_DAY
        for i in range(n_rops):
            ts = self.start + timedelta(minutes=ROP_MINUTES * i)
            ts_end = ts + timedelta(minutes=ROP_MINUTES)
            for cell in self.cells:
                self.maybe_start_fault(cell, ts)
                self.gen_rop(cell, ts)
                self.tick_fault(cell, ts_end)
        self.event_rows.sort(key=lambda r: r["timestamp"])

    def write(self, outdir):
        os.makedirs(outdir, exist_ok=True)
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
    ap = argparse.ArgumentParser(description="Synthetic gNodeB data generator")
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--cells", type=int, default=6)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--fault-rate", type=float, default=0.004,
                    help="per-cell per-ROP probability a fault starts")
    ap.add_argument("--event-sample-rate", type=float, default=0.02,
                    help="fraction of RRC attempts emitted as event traces")
    ap.add_argument("--outdir", default="./out")
    args = ap.parse_args()

    g = GnbSynth(args.cells, args.days, args.seed,
                 args.fault_rate, args.event_sample_rate)
    g.run()
    g.write(args.outdir)


if __name__ == "__main__":
    main()
