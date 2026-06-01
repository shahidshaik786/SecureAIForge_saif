# Quick Start

```bash
git clone <repo-url>
cd SecureAIFramework_saif
cp .env.example .env
./saif.sh setup
./saif.sh init-db
./saif.sh doctor --target http://127.0.0.1:8888
./saif.sh dashboard start
```

Open:

```text
http://127.0.0.1:8787
```

Use the dashboard Scan Control page to start and monitor scans.
