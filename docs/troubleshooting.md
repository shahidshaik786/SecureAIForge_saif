# Troubleshooting

## Dashboard looks stuck

Check:

```bash
./saif.sh scan status --scan-id <id>
./saif.sh logs tail --scan-id <id> --follow
```

## Schema mismatch

Run:

```bash
./saif.sh init-db
./saif.sh doctor --target http://127.0.0.1:8888
```

## Ollama problems

Check `.env`, then:

```bash
curl "$OLLAMA_BASE_URL/api/tags"
```
