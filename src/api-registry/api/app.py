import os
import re
import time
import asyncio
import logging
from typing import Dict, Any
from fastapi import FastAPI, Request, Response
import httpx
import sys

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

def is_digest(ref: str) -> bool:
    return ref.startswith("sha256:") and len(ref) == len("sha256:") + 64

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

async def _head_local_manifest(reg: str, name: str, ref_like: str, accept_hdr: str) -> httpx.Response:
    """HEAD sur le registre local pour vérifier l'existence/cohérence d'un manifest."""
    url = f"{REG_LOCAL_BASE_URL}/v2/{reg}/{name}/manifests/{ref_like}"
    async with httpx.AsyncClient(timeout=None, verify=False) as client:
        r = await client.request("HEAD", url, headers={"Accept": accept_hdr})
    return r

async def _verify_local_manifest_digest(reg: str, name: str, digest: str, accept_hdr: str) -> bool:
    """Vérifie que /manifests/<digest> existe et que Docker-Content-Digest == <digest>."""
    try:
        r = await _head_local_manifest(reg, name, digest, accept_hdr)
        if r.status_code == 200:
            dcd = r.headers.get("Docker-Content-Digest", "").lower()
            if dcd == digest.lower():
                return True
            # Certains registries ne remontent pas DCD sur HEAD; on tolère si 200
            if not dcd:
                return True
            logger.warning(f"DCD mismatch for {reg}/{name}@{digest}: got {dcd}")
    except Exception as e:
        logger.error(f"verify_local_manifest_digest error: {e}")
    return False

# ------------------- API -------------------
@app.get("/healthz")
async def healthz():
    logger.debug("Health check endpoint called")
    return {"status": "ok"}

@app.get("/metrics")
async def metrics():
    logger.debug("Metrics endpoint called")
    METRICS["inflight"] = len(inflight)
    return METRICS

@app.get("/inflight")
async def list_inflight():
    logger.debug("List inflight endpoint called")
    now = time.time()
    items = []
    for entry in list(inflight.values()):
        if entry["state"] in ("queued", "copying"):
            view = _inflight_public_view(entry)
            view["age_sec"] = round(now - entry["started"], 3)
            items.append(view)
    logger.debug(f"Inflight items: {items}")
    return {"count": len(items), "items": items}

@app.get("/ca", response_class=Response)
async def get_ca():
    """
    Retourne le certificat CA autosigné utilisé par le proxy/registry.
    Permet aux clients d'importer le CA dans leur magasin de certificats.
    """
    logger.debug("CA endpoint called")
    if not os.path.exists(REGISTRY_NFQ_CA_PATH):
        logger.debug("CA file not found")
        return Response("CA not found", status_code=404)
    with open(REGISTRY_NFQ_CA_PATH, "rb") as f:
        content = f.read()
    logger.debug("CA file served successfully")
    return Response(content, media_type="application/x-pem-file")

@app.get("/v2/")
async def ping():
    logger.debug("Ping endpoint called")
    return Response(status_code=200)

# ------------------- Core logic -------------------
async def _ensure_entry(reg: str, name: str, ref: str) -> Dict[str, Any]:
    logger.debug(f"Ensuring entry for {reg}/{name}:{ref}")
    digest_hint = ref if is_digest(ref) else None
    async with ensure_lock:
        key = f"{reg}/{name}@{digest_hint or ref}"
        entry = inflight.get(key)
        if not entry:
            logger.debug(f"Creating new entry for {key}")
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
        else:
            logger.debug(f"Using existing entry for {key}")
        entry["waiters"] += 1
        return entry

async def _rekey_entry_if_digest_known(entry: Dict[str, Any], digest: str) -> Dict[str, Any]:
    logger.debug(f"Rekeying entry for digest {digest}")
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
            logger.debug(f"Using existing entry for {new_key}")
            existing["waiters"] += max(0, entry["waiters"] - 1)
            inflight.pop(old_key, None)
            return existing
        else:
            logger.debug(f"Updating entry key from {old_key} to {new_key}")
            entry["digest"] = digest
            inflight[new_key] = entry
            inflight.pop(old_key, None)
            return entry

async def _release_entry(entry: Dict[str, Any]):
    logger.debug(f"Releasing entry for {entry['reg']}/{entry['name']}@{entry.get('digest') or entry.get('ref')}")
    reg, name = entry["reg"], entry["name"]
    key = f"{reg}/{name}@{entry.get('digest') or entry.get('ref')}"
    async with ensure_lock:
        entry["waiters"] = max(0, entry["waiters"] - 1)
        if entry["state"] not in ("queued", "copying"):
            if entry["waiters"] == 0:
                logger.debug(f"Removing entry for {key}")
                inflight.pop(key, None)

async def ensure_local(reg: str, name: str, ref: str) -> str:
    logger.debug(f"Ensuring local for {reg}/{name}:{ref}")
    entry = await _ensure_entry(reg, name, ref)
    lock: asyncio.Lock = entry["lock"]
    async with lock:
        try:
            if entry.get("digest") and is_digest(entry["digest"]):
                digest = entry["digest"]
            else:
                logger.debug(f"Resolving digest for {reg}/{name}:{ref}")
                digest = await asyncio.get_event_loop().run_in_executor(
                    None, skopeo_inspect_digest, f"{reg}/{name}:{ref}"
                )
                logger.debug(f"Resolved digest: {digest}")
            entry = await _rekey_entry_if_digest_known(entry, digest)
        except Exception as e:
            logger.error(f"Error resolving digest: {e}")
            entry["state"] = "error"
            entry["last_error"] = str(e)
            METRICS["errors"] += 1
            await _release_entry(entry)
            raise

        accept_hdr = _MANIFEST_ACCEPT

        try:
            logger.debug(f"Checking if manifest exists locally: {reg}/{name}@{digest}")
            if await local_has_manifest(reg, name, digest):
                # double check par HEAD pour s'assurer du bon DCD
                if await _verify_local_manifest_digest(reg, name, digest, accept_hdr):
                    logger.debug(f"Manifest already exists locally and verified: {digest}")
                    METRICS["ensures_hit"] += 1
                    entry["state"] = "done"
                    await _release_entry(entry)
                    return digest
        except Exception as e:
            logger.error(f"Error checking local manifest: {e}")
            entry["last_error"] = f"local_has_manifest failed: {e}"

        logger.debug(f"Manifest not found locally or not verified, copying: {reg}/{name}@{digest}")
        METRICS["ensures_miss"] += 1
        entry["state"] = "queued"

        async with sem:
            logger.debug(f"Copying manifest: {reg}/{name}@{digest}")
            entry["state"] = "copying"
            entry["attempts"] += 1
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, copy_to_local_digest, reg, name, digest
                )
                # Vérifie que le manifeste par digest est bien présent (et correct)
                if not await _verify_local_manifest_digest(reg, name, digest, accept_hdr):
                    raise RuntimeError(f"Local registry did not store manifest by digest {digest} as-is")
                logger.debug(f"Manifest copied successfully and verified: {digest}")
                entry["state"] = "done"
                await _release_entry(entry)
                return digest
            except Exception as e:
                logger.error(f"Error copying manifest: {e}")
                entry["state"] = "error"
                entry["last_error"] = str(e)
                METRICS["errors"] += 1
                await _release_entry(entry)
                raise

# ------------------- Ensure status -------------------
@app.get("/ensure-status/{reg}/{name}/{ref}")
async def ensure_status(reg: str, name: str, ref: str, request: Request):
    """
    200 si présent localement **par digest** (ou par tag -> résolu puis vérifié par digest).
    202 si en cours (avec Retry-After).
    404 sinon.
    """
    logger.debug(f"Checking ensure status for {reg}/{name}:{ref}")
    accept_hdr = request.headers.get("accept") or _MANIFEST_ACCEPT

    # Si ref est un digest : on NE fait PAS de fallback vers le tag synthétique.
    if is_digest(ref):
        try:
            if await local_has_manifest(reg, name, ref):
                if await _verify_local_manifest_digest(reg, name, ref, accept_hdr):
                    return Response(status_code=200)
        except Exception as e:
            logger.debug(f"Error checking local manifest by digest: {e}")
        # si HEAD par digest ne passe pas, c'est 404 (pas de faux positif)
        head = await _head_local_manifest(reg, name, ref, accept_hdr)
        if head.status_code == 200:
            return Response(status_code=200)
        # sinon on continue sur l'état inflight
    else:
        # ref = tag : on résout le digest puis on vérifie par digest
        try:
            digest = await asyncio.get_event_loop().run_in_executor(
                None, skopeo_inspect_digest, f"{reg}/{name}:{ref}"
            )
            if await local_has_manifest(reg, name, digest):
                if await _verify_local_manifest_digest(reg, name, digest, accept_hdr):
                    return Response(status_code=200)
        except Exception as e:
            logger.debug(f"Error resolving/checking tag: {e}")
            # on continue

    # Vérifie les ensures en cours
    logger.debug("Checking inflight entries for matching ref or digest")
    for e in inflight.values():
        if e["reg"] == reg and e["name"] == name:
            if e.get("digest") == ref or e.get("ref") == ref:
                if e["state"] in ("queued", "copying"):
                    logger.debug(f"Manifest is in progress: {e}")
                    return Response(status_code=202, headers={"Retry-After": "2"})

    logger.debug("Manifest not found locally or in progress")
    return Response(status_code=404)

# ------------------- Routes -------------------
@app.api_route("/v2/{reg}/{path:path}", methods=["GET", "HEAD"])
async def v2_router(request: Request, reg: str, path: str):
    logger.debug(f"Incoming request: {request.method} /v2/{reg}/{path}")
    METRICS["requests_total"] += 1

    q = dict(request.query_params)
    is_async = q.get("async") in ("1", "true", "yes")
    prefer = request.headers.get("Prefer", "")
    full_path = f"/v2/{reg}/{path}"

    m = parse_manifest_path(full_path)
    if m:
        logger.debug(f"Manifest path matched: {m}")
        METRICS["ensures"] += 1
        reg_m, name, ref = m

        # Mode async: déclenche en arrière-plan et 202 de suite
        if is_async or "respond-async" in prefer.lower():
            logger.debug(f"Async mode for {reg_m}/{name}:{ref}")
            async def _bg():
                try:
                    await ensure_local(reg_m, name, ref)
                except Exception as e:
                    logger.error(f"Error in background task: {e}")
            asyncio.create_task(_bg())
            logger.debug(f"Background task created for {reg_m}/{name}:{ref}")
            return Response(
                status_code=202,
                headers={"Location": f"/ensure-status/{reg_m}/{name}/{ref}", "Retry-After": "2"},
            )

        # Mode sync
        logger.debug(f"Sync mode for {reg_m}/{name}:{ref}")
        try:
            digest = await ensure_local(reg_m, name, ref)
            logger.debug(f"Ensured local for {reg_m}/{name}:{ref} -> {digest}")
        except Exception as e:
            logger.error(f"Error ensuring local: {e}")
            return Response(str(e), status_code=502)

        accept_hdr = request.headers.get("accept") or _MANIFEST_ACCEPT

        async with httpx.AsyncClient(timeout=None, verify=False) as client:
            # IMPORTANT :
            # - si le client a demandé par digest, on NE fait PAS de fallback vers un tag synthétique.
            # - si le client a demandé par tag, on sert directement par digest.
            if is_digest(ref):
                url = f"{REG_LOCAL_BASE_URL}/v2/{reg_m}/{name}/manifests/{digest}"
                logger.debug(f"Fetching digest directly (no fallback): {url}")
                upstream = await client.request(request.method, url, headers={"Accept": accept_hdr})
                return Response(
                    content=upstream.content,
                    status_code=upstream.status_code,
                    headers=dict(upstream.headers),
                )
            else:
                # ref = tag : sert le manifeste canonique par digest (fallback tag synthétique en dernier recours)
                candidate_refs = [digest, digest_to_tag(digest)]
                last = None
                for target_ref in candidate_refs:
                    url = f"{REG_LOCAL_BASE_URL}/v2/{reg_m}/{name}/manifests/{target_ref}"
                    logger.debug(f"Trying URL: {url}")
                    upstream = await client.request(request.method, url, headers={"Accept": accept_hdr})
                    if upstream.status_code != 404:
                        logger.debug(f"Found manifest at {url}")
                        return Response(
                            content=upstream.content,
                            status_code=upstream.status_code,
                            headers=dict(upstream.headers),
                        )
                    last = upstream
                logger.debug("No manifest found for tag path, returning last response")
                return Response(
                    content=last.content if last else b"",
                    status_code=last.status_code if last else 404,
                    headers=dict(last.headers) if last else {},
                )

    b = parse_blob_path(full_path)
    if b:
        logger.debug(f"Blob path matched: {b}")
        reg_b, name, dg = b
        url = f"{REG_LOCAL_BASE_URL}/v2/{reg_b}/{name}/blobs/{dg}"
        logger.debug(f"Fetching blob from {url}")
        async with httpx.AsyncClient(timeout=None, verify=False) as client:
            upstream = await client.request(request.method, url)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=dict(upstream.headers),
        )

    logger.debug("Path not matched, returning 404")
    return Response(status_code=404)

if __name__ == "__main__":
    logger.debug("Starting server")
    import uvicorn
    uvicorn.run("app:app", host=LISTEN_HOST, port=LISTEN_PORT, reload=False)
