Synthetic 5G RAN + Core + IMS observability dataset
===================================================
Window : 2026-07-06 00:00 to 2026-07-09 00:00 (3 days, 15-min ROPs)
Seed   : 21   (rerun scripts with same args to reproduce)

ran/  - gnb_synth.py output (6 NR cells)
    counters.csv / kpis.csv / alarms.csv / events.csv
    (TS 28.552-style counters, X.733-style alarms)

core/ - core_synth.py output (Open5GS-style)
    core.log + per-NF: amf, smf, upf, ausf, udm, pcf, nssf .log
    counters.csv / kpis.csv / alarms.csv / events.csv

ims/  - ims_synth.py output (Kamailio / PyHSS / RTPEngine / BIND)
    ims.log + per-node: pcscf, icscf, scscf, pyhss, rtpengine, dns .log
    counters.csv / kpis.csv / alarms.csv / events.csv
    KPIs: registration SR, call setup SR, ASR, call drop rate, MOS

Cross-correlation chain (RAN -> Core -> IMS):
    RAN AMF_UNREACHABLE / CELL_DOWN  -> core amf.log N2/SCTP lines + traffic dip
    Core UPF_PFCP_DOWN               -> IMS call failures (500 media),
                                        RTPEngine media timeouts, MOS dip
    Core N2_SCTP_FLAP                -> IMS registration/call traffic dip
    Join structured events on trace_id (within a layer);
    join across layers on rop_start.

Generation commands:
    python3 gnb_synth.py  --days 3 --cells 6 --seed 21 --fault-rate 0.01 --outdir ./ran
    python3 core_synth.py --days 3 --seed 21 --fault-rate 0.03 --gnb-alarms ./ran/alarms.csv --outdir ./core
    python3 ims_synth.py  --days 3 --seed 21 --core-alarms ./core/alarms.csv --outdir ./ims
