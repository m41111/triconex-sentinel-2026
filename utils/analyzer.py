"""TriStation protocol analyzer with anomaly scoring."""

from datetime import datetime, timedelta
from collections import defaultdict


# TriStation function codes (known)
TRISTATION_FUNCS = {
    0x01: "ALLOCATE_PROGRAM",
    0x02: "ALLOCATE_PROGRAM_RESP",
    0x05: "GET_CP_STATUS",
    0x06: "GET_CP_STATUS_RESP",
    0x09: "SET_PROJ_INFO",
    0x0A: "SET_PROJ_INFO_RESP",
    0x31: "DOWNLOAD",
    0x32: "DOWNLOAD_RESP",
    0x37: "GO_TO_PROGRAM",
    0x38: "GO_TO_PROGRAM_RESP",
}

DANGEROUS_FUNCS = {0x31, 0x37, 0x09}


class TriStationAnalyzer:
    def __init__(self, known_stations, controllers, thresholds, alert_manager, verbose=False):
        self.known_stations = set(known_stations)
        self.controllers = {c["ip"]: c for c in controllers}
        self.thresholds = thresholds
        self.alert_mgr = alert_manager
        self.verbose = verbose

        self.sessions = defaultdict(lambda: {"first_seen": None, "count": 0, "funcs": []})
        self.anomaly_scores = defaultdict(float)
        self.alerts_raised = 0

    def process_packet(self, pkt, pkt_num):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        payload = bytes(pkt["UDP"].payload)

        if len(payload) < 4:
            return

        func_code = payload[0]
        func_name = TRISTATION_FUNCS.get(func_code, f"UNKNOWN_0x{func_code:02X}")
        ts = datetime.utcnow()

        session_key = f"{src_ip}->{dst_ip}"
        session = self.sessions[session_key]
        if session["first_seen"] is None:
            session["first_seen"] = ts
        session["count"] += 1
        session["funcs"].append(func_code)

        score_delta = 0.0

        if src_ip not in self.known_stations:
            score_delta += 3.0
            if self.verbose:
                print(f"  [!] Unknown engineering station: {src_ip}")

        if func_code in DANGEROUS_FUNCS:
            score_delta += 2.5
            if self.verbose:
                print(f"  [!] Dangerous function: {func_name}")

        if session["count"] > self.thresholds.get("max_eng_sessions", 2) * 50:
            score_delta += 1.5

        self.anomaly_scores[src_ip] += score_delta
        current_score = self.anomaly_scores[src_ip]

        if self.verbose:
            print(f"  [{ts.strftime('%H:%M:%S')}] #{pkt_num} {session_key} func={func_name} score={current_score:.1f}")

        trigger = self.thresholds.get("anomaly_score_trigger", 7.5)
        if current_score >= trigger:
            self.alerts_raised += 1
            self.alert_mgr.send_alert(
                severity="HIGH",
                source=src_ip,
                target=dst_ip,
                score=current_score,
                detail=f"Anomaly threshold exceeded. Last function: {func_name}"
            )
            self.anomaly_scores[src_ip] = 0.0

    def print_summary(self):
        print(f"\n{'='*50}")
        print(f"  Session Summary")
        print(f"{'='*50}")
        print(f"  Total sessions: {len(self.sessions)}")
        print(f"  Alerts raised:  {self.alerts_raised}")
        for src, score in sorted(self.anomaly_scores.items(), key=lambda x: -x[1]):
            flag = " [!]" if src not in self.known_stations else ""
            print(f"  {src}: score={score:.1f}{flag}")
