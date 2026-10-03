"""Alert routing for sentinel events."""

import socket
import json
from datetime import datetime


class AlertManager:
    def __init__(self, config):
        self.syslog_server = config.get("syslog_server", "127.0.0.1")
        self.syslog_port = config.get("syslog_port", 514)
        self.email_enabled = config.get("email_enabled", False)
        self.alert_log = []

    def send_alert(self, severity, source, target, score, detail):
        alert = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": severity,
            "source_ip": source,
            "target_ip": target,
            "anomaly_score": round(score, 2),
            "detail": detail,
            "tool": "triconex-sentinel"
        }

        self.alert_log.append(alert)
        self._print_alert(alert)
        self._send_syslog(alert)

    def _print_alert(self, alert):
        sev = alert["severity"]
        marker = "\033[91m[CRITICAL]\033[0m" if sev == "CRITICAL" else f"\033[93m[{sev}]\033[0m"
        print(f"\n  {marker} ALERT — {alert['detail']}")
        print(f"    Source: {alert['source_ip']} → Target: {alert['target_ip']}")
        print(f"    Score: {alert['anomaly_score']} | Time: {alert['timestamp']}")

    def _send_syslog(self, alert):
        try:
            msg = f"<134>{json.dumps(alert)}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), (self.syslog_server, self.syslog_port))
            sock.close()
        except Exception:
            pass
