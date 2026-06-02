# Quick Start

```bash
git clone https://github.com/shahidshaik786/SecureAIForge_saif.git
cd SecureAIForge_saif
cp .env.example .env
./saif.sh setup
./saif.sh init-db
./saif.sh doctor --target http://127.0.0.1:8888
./saif.sh dashboard start
```

Open:

```text
http://192.168.0.7:8787
```

The dashboard binds to all interfaces by default with `SAIF_DASHBOARD_HOST=0.0.0.0`. Use `http://127.0.0.1:8787` from the same machine, or `http://192.168.0.7:8787` from another device on the LAN.

Use the dashboard Scan Control page to start and monitor scans.
