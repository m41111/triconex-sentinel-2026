#!/usr/bin/env python3
"""
triconex-sentinel — passive TriStation protocol monitor
Monitors UDP/1502 traffic for anomalous SIS communication patterns.
"""

import argparse
import sys
import yaml
from datetime import datetime
from utils.capture import PacketCapture
from utils.analyzer import TriStationAnalyzer
from utils.alerts import AlertManager

__version__ = "0.4.1"

def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def banner():
    print(f"""
    ╔══════════════════════════════════════╗
    ║   triconex-sentinel v{__version__}          ║
    ║   ICS/SIS Network Monitor            ║
    ╚══════════════════════════════════════╝
    """)

def main():
    parser = argparse.ArgumentParser(description="Triconex SIS network sentinel")
    parser.add_argument("--interface", "-i", default="eth0", help="Network interface to monitor")
    parser.add_argument("--config", "-c", default="config.yaml", help="Configuration file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Parse config and exit without capturing")
    args = parser.parse_args()

    banner()

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"[ERROR] Config file not found: {args.config}")
        print("  Copy config.example.yaml to config.yaml and adjust settings.")
        sys.exit(1)

    alert_mgr = AlertManager(config.get("alerts", {}))
    analyzer = TriStationAnalyzer(
        known_stations=config["sentinel"].get("known_engineering_stations", []),
        controllers=config["sentinel"].get("monitored_controllers", []),
        thresholds=config.get("thresholds", {}),
        alert_manager=alert_mgr,
        verbose=args.verbose
    )

    if args.dry_run:
        print("[OK] Configuration valid. Dry run complete.")
        sys.exit(0)

    capture = PacketCapture(
        interface=args.interface,
        port=config["sentinel"].get("tristation_port", 1502),
        callback=analyzer.process_packet
    )

    print(f"[*] Monitoring {args.interface} for TriStation traffic (UDP/{config['sentinel'].get('tristation_port', 1502)})")
    print(f"[*] Known engineering stations: {len(config.get('known_engineering_stations', []))}")
    print(f"[*] Monitored controllers: {len(config.get('monitored_controllers', []))}")
    print(f"[*] Anomaly threshold: {config.get('thresholds', {}).get('anomaly_score_trigger', 7.5)}")
    print(f"[*] Started at {datetime.utcnow().isoformat()}Z")
    print()

    try:
        capture.start()
    except KeyboardInterrupt:
        print("\n[*] Sentinel stopped by operator.")
        analyzer.print_summary()

if __name__ == "__main__":
    main()
