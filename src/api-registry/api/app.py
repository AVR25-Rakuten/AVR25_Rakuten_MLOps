import os
import re
import time
import asyncio
from typing import Dict, Any

from fastapi import FastAPI, Request, Response
import httpx

import sys
sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    skopeo_inspect_digest,
    copy_to_local_digest,
    local_has_manifest,
    REG_LOCAL_BASE_URL,
)

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8000"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
MAX_CONCURRENT_COPIES = int(os.getenv("MAX_CONCURRENT_COPIES", "4"))
REGISTRY_NFQ_CA_PATH = os.getenv("REGISTRY_NFQ_CA_PATH", "/certs/nfq-registry-ca.pem")

# Concurrency + déduplication
ensure_lock = asyncio.Lock()
sem = asyncio.Semaphore(MAX_CONCURRENT_COPIES)
inflight: Dict[str, Dict[str, Any]] = {}

app = FastAPI()
METRICS = {
    "requests_total": 0,
    "ensures": 0,
    "ensures_hit": 0,
    "ensures_miss": 0,
    "errors": 0,
}

_MANIFEST_ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/json",
])

# ------------------- Helpers -------------------

def parse_manifest_path(path: str):
    m = re.match(r"^/v2/([^/]+)/(.+)/manifests/([^/]+)$", path)
    return m.groups() if m else None

def parse_blob_path(path: str):
    m = re.match(r"^/v2/([^/]+)/(.+)/blobs/(sha256:[0-9a-f]{64})$", path)
    return m.groups() if m else None

def digest_to_tag(digest: str) -> str:
    # "sha256:abcd..." -> "bydigest-sha256-abcd..."
    return f"bydigest-{digest.replace(':','-')}"

def _inflight_public_view(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key": f"{entry['reg']}/{entry['name']}@{entry.get('digest') or entry.get('ref')}",
        "reg": entry["reg"],
        "name": entry["name"],
        "ref": entry.get("ref"),
        "digest": entry.get("digest"),
        "state": entry["state"],
        "started": entry["started"],
        "age_sec": round(time.time() - entry["started"], 3),
        "waiters": entry["waiters"],
        "attempts": entry["attempts"],
        "last_error": entry.get("last_error"),
    }

# ------------------- API -------------------

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

@app.get("/metrics")
async def metrics():
    METRICS["inflight"] = len(inflight)
    return METRICS

@app.get("/inflight")
async def list_inflight():
    now = time.time()
    items = []
    for entry in list(inflight.values()):
        if entry["state"] in ("queued", "copying"):
            view = _inflight_public_view(entry)
            view["age_sec"] = round(now - entry["started"], 3)
            items.append(view)
    return {"count": len(items), "items": items}

@app.get("/ca", response_class=Response)
async def get_ca():
    """
    Retourne le certificat CA autosigné utilisé par le proxy/registry.
    Permet aux clients d'importer le CA dans leur magasin de certificats.
    """
    if not os.path.exists(REGISTRY_NFQ_CA_PATH):
        return Response("CA not found", status_code=404)
    with open(REGISTRY_NFQ_CA_PATH, "rb") as f:
        content = f.read()
    # application/x-pem-file convient pour un .pem
    return Response(content, media_type="application/x-pem-file")

@app.get("/v2/")
async def ping():
    return Response(status_code=200)

# ------------------- Core logic -------------------

async def _ensure_entry(reg: str, name: str, ref: str) -> Dict[str, Any]:
    digest_hint = ref if ref.startswith("sha256:") else None
    async with ensure_lock:
        key = f"{reg}/{name}@{digest_hint or ref}"
        entry = inflight.get(key)
        if not entry:
            entry = {
                "lock": asyncio.Lock(),
                "state": "queued",
                "started": time.time(),
                "reg": reg,
                "name": name,
                "ref": ref,
                "digest": digest_hint,
                "waiters": 0,
                "attempts": 0,
                "last_error": None,
            }
            inflight[key] = entry
        entry["waiters"] += 1
        return entry

async def _rekey_entry_if_digest_known(entry: Dict[str, Any], digest: str) -> Dict[str, Any]:
    if entry.get("digest") == digest:
        return entry
    reg, name = entry["reg"], entry["name"]
    old_key = f"{reg}/{name}@{entry.get('digest') or entry.get('ref')}"
    new_key = f"{reg}/{name}@{digest}"
    async with ensure_lock:
        if old_key == new_key:
            return entry
        existing = inflight.get(new_key)
        if existing:
            existing["waiters"] += max(0, entry["waiters"] - 1)
            inflight.pop(old_key, None)
            return existing
        else:
            entry["digest"] = digest
            inflight[new_key] = entry
            inflight.pop(old_key, None)
            return entry

async def _release_entry(entry: Dict[str, Any]):
    reg, name = entry["reg"], entry["name"]
    key = f"{reg}/{name}@{entry.get('digest') or entry.get('ref')}"
    async with ensure_lock:
        entry["waiters"] = max(0, entry["waiters"] - 1)
        if entry["state"] not in ("queued", "copying"):
            if entry["waiters"] == 0:
                inflight.pop(key, None)

async def ensure_local(reg: str, name: str, ref: str) -> str:
    entry = await _ensure_entry(reg, name, ref)
    lock: asyncio.Lock = entry["lock"]
    async with lock:
        try:
            if entry.get("digest") and entry["digest"].startswith("sha256:"):
                digest = entry["digest"]
            else:
                digest = await asyncio.get_event_loop().run_in_executor(
                    None, skopeo_inspect_digest, f"{reg}/{name}:{ref}"
                )
            entry = await _rekey_entry_if_digest_known(entry, digest)
        except Exception as e:
            entry["state"] = "error"
            entry["last_error"] = str(e)
            METRICS["errors"] += 1
            await _release_entry(entry)
            raise

        try:
            if await local_has_manifest(reg, name, digest):
                METRICS["ensures_hit"] += 1
                entry["state"] = "done"
                await _release_entry(entry)
                return digest
        except Exception as e:
            entry["last_error"] = f"local_has_manifest failed: {e}"

        METRICS["ensures_miss"] += 1
        entry["state"] = "queued"

        async with sem:
            entry["state"] = "copying"
            entry["attempts"] += 1
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, copy_to_local_digest, reg, name, digest
                )
                entry["state"] = "done"
                await _release_entry(entry)
                return digest
            except Exception as e:
                entry["state"] = "error"
                entry["last_error"] = str(e)
                METRICS["errors"] += 1
                await _release_entry(entry)
                raise

# ------------------- Ensure status -------------------

@app.get("/ensure-status/{reg}/{name}/{ref}")
async def ensure_status(reg: str, name: str, ref: str, request: Request):
    """
    200 si présent localement (par digest ou par tag synthétique).
    202 si en cours (avec Retry-After).
    404 sinon.
    """
    accept_hdr = request.headers.get("accept") or _MANIFEST_ACCEPT

    async def _local_head(ref_like: str) -> bool:
        """HEAD vers le registre local pour vérifier l'existence d'un manifest."""
        url = f"{REG_LOCAL_BASE_URL}/v2/{reg}/{name}/manifests/{ref_like}"
        async with httpx.AsyncClient(timeout=None, verify=False) as client:
            r = await client.request("HEAD", url, headers={"Accept": accept_hdr})
            return r.status_code != 404

    # 1) Si ref est un digest : teste local_has_manifest puis fallback HEAD sur bydigest-…
    if ref.startswith("sha256:"):
        try:
            if await local_has_manifest(reg, name, ref):
                return Response(status_code=200)
        except Exception:
            pass
        # fallback HTTP sur le tag synthétique
        if await _local_head(digest_to_tag(ref)):
            return Response(status_code=200)

    # 2) Si ref est un tag : tente de résoudre le digest puis testes
    else:
        try:
            digest = await asyncio.get_event_loop().run_in_executor(
                None, skopeo_inspect_digest, f"{reg}/{name}:{ref}"
            )
            try:
                if await local_has_manifest(reg, name, digest):
                    return Response(status_code=200)
            except Exception:
                pass
            if await _local_head(digest_to_tag(digest)):
                return Response(status_code=200)
        except Exception:
            # impossible de résoudre, on continue
            pass

    # 3) Vérifie les ensures en cours
    for e in inflight.values():
        if e["reg"] == reg and e["name"] == name:
            if e.get("digest") == ref or e.get("ref") == ref:
                if e["state"] in ("queued", "copying"):
                    return Response(status_code=202, headers={"Retry-After": "2"})

    # 4) Rien trouvé
    return Response(status_code=404)

# ------------------- Routes -------------------

@app.api_route("/v2/{reg}/{path:path}", methods=["GET", "HEAD"])
async def v2_router(request: Request, reg: str, path: str):
    METRICS["requests_total"] += 1
    q = dict(request.query_params)
    is_async = q.get("async") in ("1", "true", "yes")
    prefer = request.headers.get("Prefer", "")
    full_path = f"/v2/{reg}/{path}"

    m = parse_manifest_path(full_path)
    if m:
        METRICS["ensures"] += 1
        reg_m, name, ref = m

        # Mode async: déclenche en arrière-plan et 202 de suite
        if is_async or "respond-async" in prefer.lower():
            async def _bg():
                try:
                    await ensure_local(reg_m, name, ref)
                except Exception:
                    pass
            asyncio.create_task(_bg())
            return Response(
                status_code=202,
                headers={"Location": f"/ensure-status/{reg_m}/{name}/{ref}", "Retry-After": "2"},
            )

        # Mode sync: ensure local puis proxy via refs existantes (digest -> fallback bydigest-…)
        try:
            digest = await ensure_local(reg_m, name, ref)
        except Exception as e:
            return Response(str(e), status_code=502)

        accept_hdr = request.headers.get("accept") or _MANIFEST_ACCEPT
        candidate_refs = [digest, digest_to_tag(digest)]

        async with httpx.AsyncClient(timeout=None, verify=False) as client:
            last = None
            for target_ref in candidate_refs:
                url = f"{REG_LOCAL_BASE_URL}/v2/{reg_m}/{name}/manifests/{target_ref}"
                upstream = await client.request(
                    request.method, url, headers={"Accept": accept_hdr}
                )
                if upstream.status_code != 404:
                    return Response(
                        content=upstream.content,
                        status_code=upstream.status_code,
                        headers=dict(upstream.headers),
                    )
                last = upstream

        # Si tout est 404, renvoyer le dernier 404
        return Response(
            content=last.content if last else b"",
            status_code=last.status_code if last else 404,
            headers=dict(last.headers) if last else {},
        )

    b = parse_blob_path(full_path)
    if b:
        reg_b, name, dg = b
        url = f"{REG_LOCAL_BASE_URL}/v2/{reg_b}/{name}/blobs/{dg}"
        async with httpx.AsyncClient(timeout=None, verify=False) as client:
            upstream = await client.request(request.method, url)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=dict(upstream.headers),
        )

    return Response(status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=LISTEN_HOST, port=LISTEN_PORT, reload=False)
