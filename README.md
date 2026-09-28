# triconex-sentinel-2026

Lightweight network sentinel for monitoring Triconex Safety Instrumented System (SIS) environments. Passively monitors TriStation protocol traffic and flags anomalous communication patterns consistent with known ICS threat activity.

## Features

- Passive TriStation protocol monitoring (UDP/1502)
- Anomaly detection for unauthorized engineering workstation connections
- Alert correlation with known IOC patterns
- Configurable thresholds and alert routing
- Lightweight — runs on minimal hardware (Raspberry Pi compatible)

## Quick Start

```bash
pip install -r requirements.txt
python sentinel.py --interface eth0 --config config.yaml
```

## Configuration

Copy `config.example.yaml` to `config.yaml` and adjust for your environment. See `docs/` for deployment guides.

## Disclaimer

This tool is provided for authorized security monitoring only. Ensure proper authorization before deploying in any OT/ICS environment.

## License

MIT
