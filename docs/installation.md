# Installation

SAIF - Secure AI Forge is an AI-assisted authorized Web/API security testing, evidence, and reporting forge.

SAIF runs from WSL Ubuntu with PostgreSQL. SQLite is not supported.

```bash
git clone https://github.com/shahidshaik786/SecureAIForge_saif.git
cd SecureAIForge_saif
cp .env.example .env
./saif.sh setup
./saif.sh init-db
./saif.sh doctor --target http://127.0.0.1:8888
```

Ollama must be installed separately and reachable through `OLLAMA_BASE_URL`.

Google also uses SAIF to refer to Secure AI Framework. This project uses SAIF as Secure AI Forge and is independent and not affiliated with Google.
