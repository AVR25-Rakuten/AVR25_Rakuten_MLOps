# registry-nfq-proxy (FastAPI) — Nginx health only

- **FastAPI** joue le rôle de **proxy de registry** (port 8000, TLS self-signed par défaut).
- **Nginx+fcgiwrap** ne sert qu'un **/health** sur 443.
- **Sans NFQUEUE**. Préchargement déclenché par GET/HEAD des manifests.
- États transitoires via `202 Accepted` et endpoint `GET /ensure-status/{reg}/{name}/{ref}`.

## Démarrer
```bash
docker compose up -d --build
curl -k https://localhost/health
curl -kI https://localhost:8000/v2/
```

## Copier avec skopeo
```bash
# push vers tampon via proxy
skopeo copy --retry-times 3 docker://docker.io/library/busybox:latest \      docker://localhost:8000/library/busybox:itestpush --dest-tls-verify=false

# pull depuis le proxy
skopeo copy --retry-times 3 --src-tls-verify=false \      docker://localhost:8000/library/busybox:itestpush dir:/tmp/out
```

## Tests
```bash
docker exec -it registry-nfq run-tests
```

## Variables utiles
- `REG_LOCAL_BASE_URL` (default: `http://internal-registry:5000`)
- `TAMPON_REGISTRY` (default: `internal-registry:5000`)
- `INSECURE_SRC`, `INSECURE_DEST`
- `APP_TLS` (true/false), `LISTEN_HOST`, `LISTEN_PORT`
