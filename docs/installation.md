# Installation

SAIF runs from WSL Ubuntu with PostgreSQL. SQLite is not supported.

```bash
git clone <repo-url>
cd SecureAIFramework_saif
cp .env.example .env
./saif.sh setup
./saif.sh init-db
./saif.sh doctor --target http://127.0.0.1:8888
```

Ollama must be installed separately and reachable through `OLLAMA_BASE_URL`.
