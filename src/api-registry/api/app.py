import os
import re
import time
import asyncio
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Response
import httpx

import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    skopeo_inspect_digest,
    copy_to_local_digest,
    copy_to_local_tag,
    local_has_manifest,
    REG_LOCAL_BASE_URL,  # même valeur que côté utils
)

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8000"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
MAX_CONCURRENT_COPIES = int(os.getenv("MAX_CONCURRENT_COPIES", "4"))

# Concurrency + dédup
ensure_lock = asyncio.Lock()  # protège l'accès à 'inflight'
sem = asyncio.Semaphore(MAX_CONCURRENT_COPIES)

# Clé = "reg/name@sha256:..."
# Valeur = dict(state, lock, started, reg, name, ref, digest, waiters, attempts, last_error)
inflight: Dict[str, Dict[str, Any]] = {}

app = FastAPI()
METRICS = {
    "requests_total": 0,
    "ensures": 0,
    "ensures_hit": 0,
    "ensures_miss": 0,
    "errors": 0,
}

_MANIFEST_ACCEPT = ",".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/json",
    ]
)

# --------- Helpers de parsing des chemins V2 ---------
def parse_manifest_path(path: str):
    # /v2/<reg>/<name>/manifests/<ref>
    m = re.match(r"^/v2/([^/]+)/(.+)/manifests/([^/]+)$", path)
    return m.groups() if m else None


def parse_blob_path(path: str):
    # /v2/<reg>/<name>/blobs/sha256:....
    m = re.match(r"^/v2/([^/]+)/(.+)/blobs/(sha256:[0-9a-f]{64})$", path)
    return m.groups() if m else None


def _inflight_public_view(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key": f"{entry['reg']}/{entry['name']}@{entry.get('digest') or entry.get('ref')}",
        "reg": entry["reg"],
        "name": entry["name"],
        "ref": entry.get("ref"),
        "digest": entry.get("digest"),
        "state": entry["state"],  # queued|copying
        "started": entry["started"],
        "age_sec": round(time.time() - entry["started"], 3),
        "waiters": entry["waiters"],
        "attempts": entry["attempts"],
        "last_error": entry.get("last_error"),
    }


async def _ensure_entry(reg: str, name: str, ref: str) -> Dict[str, Any]:
    """
    Renvoie l'entrée inflight (existante ou nouvellement créée) + son lock.
    Incrémente 'waiters'.
    """
    if ref.startswith("sha256:"):
        digest_hint = ref
    else:
        digest_hint = None

    async with ensure_lock:
        # Si on a déjà le digest, on peut clé directement; sinon on clé temporairement par ref
        # mais on remplacera par le vrai digest dès qu'on le connaît.
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
    """
    Si l'entrée a été créée à partir d'un tag (ref) et que le digest est connu,
    on déplace la clé inflight vers 'reg/name@digest' pour dédup stricte.
    """
    if entry.get("digest") == digest:
        return entry

    reg, name = entry["reg"], entry["name"]
    old_key = f"{reg}/{name}@{entry.get('digest') or entry.get('ref')}"
    new_key = f"{reg}/{name}@{digest}"

    async with ensure_lock:
        if old_key == new_key:
            return entry
        # Si une entrée avec digest existe déjà, on fusionne 'waiters' et on renvoie l'autre.
        existing = inflight.get(new_key)
        if existing:
            existing["waiters"] += max(0, entry["waiters"] - 1)
            # On efface l'ancienne
            inflight.pop(old_key, None)
            return existing
        else:
            # Rekey: on remplace la clé
            entry["digest"] = digest
            inflight[new_key] = entry
            inflight.pop(old_key, None)
            return entry


async def _release_entry(entry: Dict[str, Any]):
    """
    Décrémente 'waiters'; si plus personne n'attend et state != copying/queued,
    on supprime l'entrée de la table inflight.
    """
    reg, name = entry["reg"], entry["name"]
    key = f"{reg}/{name}@{entry.get('digest') or entry.get('ref')}"
    async with ensure_lock:
        entry["waiters"] = max(0, entry["waiters"] - 1)
        # On ne garde dans inflight que ce qui est "en cours" (queued/copying)
        if entry["state"] not in ("queued", "copying"):
            # 'done' ou 'error' -> on retire si plus d'attente
            if entry["waiters"] == 0:
                inflight.pop(key, None)


# ------------------- API -------------------
@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/metrics")
async def metrics():
    # Ajoute métrique runtime des inflight
    METRICS["inflight"] = len(inflight)
    return METRICS


@app.get("/inflight")
async def list_inflight():
    """
    Liste des ensures en cours (queued/copying).
    """
    # Snapshot non bloquant
    items = []
    now = time.time()
    for entry in list(inflight.values()):
        if entry["state"] in ("queued", "copying"):
            view = _inflight_public_view(entry)
            # rafraîchit l'age
            view["age_sec"] = round(now - entry["started"], 3)
            items.append(view)
    return {"count": len(items), "items": items}


@app.get("/v2/")
async def ping():
    return Response(status_code=200)


async def ensure_local(reg: str, name: str, ref: str) -> str:
    """
    Garantit que l'image (par digest) est présente dans le registry tampon.
    Retourne le digest final (sha256:...).
    Dédup stricte par digest et concurrency limit via semaphore.
    """
    entry = await _ensure_entry(reg, name, ref)
    lock: asyncio.Lock = entry["lock"]

    async with lock:
        # Si on connait pas le digest, résout-le (hors section critique des copies, mais sous lock d'entrée)
        try:
            if entry.get("digest") and entry["digest"].startswith("sha256:"):
                digest = entry["digest"]
            else:
                # ref -> digest
                digest = await asyncio.get_event_loop().run_in_executor(
                    None, skopeo_inspect_digest, f"{reg}/{name}:{ref}"
                )
            # Rekey par digest pour dédup stricte
            entry = await _rekey_entry_if_digest_known(entry, digest)
        except Exception as e:
            entry["state"] = "error"
            entry["last_error"] = str(e)
            METRICS["errors"] += 1
            await _release_entry(entry)
            raise

        # Hit local ?
        try:
            if await local_has_manifest(reg, name, digest):
                METRICS["ensures_hit"] += 1
                entry["state"] = "done"
                await _release_entry(entry)
                return digest
        except Exception as e:
            # On loggue mais on tente la copie (peut réparer)
            entry["last_error"] = f"local_has_manifest failed: {e}"

        METRICS["ensures_miss"] += 1
        entry["state"] = "queued"

        # Limite globale de copies concurrentes
        async with sem:
            entry["state"] = "copying"
            entry["attempts"] += 1
            try:
                # Copie par DIGEST -> dest tag synthétique gérée côté utils
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


@app.get("/ensure-status/{reg}/{name}/{ref}")
async def ensure_status(reg: str, name: str, ref: str, request: Request):
    """
    200 si déjà présent localement (par digest si ref=digest, sinon on tente HEAD via accept).
    202 si en cours (avec Retry-After).
    404 si non trouvé et pas en cours.
    """
    # Tente HEAD local direct par ref (si digest) sinon par Accept qui peut renvoyer le digest
    try:
        if ref.startswith("sha256:"):
            if await local_has_manifest(reg, name, ref):
                return Response(status_code=200)
        else:
            # On résout le digest rapidement (non bloquant si call distant lent -> 202)
            try:
                digest = await asyncio.get_event_loop().run_in_executor(
                    None, skopeo_inspect_digest, f"{reg}/{name}:{ref}"
                )
                if await local_has_manifest(reg, name, digest):
                    return Response(status_code=200)
            except Exception:
                pass
    except Exception:
        pass

    # Regarder inflight
    key_digest = f"{reg}/{name}@{ref if ref.startswith('sha256:') else ref}"
    # Cherche entrée par digest si possible
    for k, e in inflight.items():
        if e["reg"] == reg and e["name"] == name:
            if e.get("digest") == ref or e.get("ref") == ref:
                if e["state"] in ("queued", "copying"):
                    return Response(status_code=202, headers={"Retry-After": "2"})
    # Rien en cours
    return Response(status_code=404)


@app.api_route("/v2/{reg}/{path:path}", methods=["GET", "HEAD"])
async def v2_router(request: Request, reg: str, path: str):
    """
    Proxy/ensure des endpoints Docker Registry:
      - /v2/<reg>/<name>/manifests/<ref>
      - /v2/<reg>/<name>/blobs/<sha256:...>
    Support 'async=1' pour un 202 immédiat avec prefetch en arrière-plan.
    """
    METRICS["requests_total"] += 1
    q = dict(request.query_params)
    is_async = q.get("async") in ("1", "true", "yes")
    prefer = request.headers.get("Prefer", "")

    full_path = f"/v2/{reg}/{path}"
    m = parse_manifest_path(full_path)
    if m:
        METRICS["ensures"] += 1
        reg_m, name, ref = m

        # Mode async (respond-async)
        if is_async or "respond-async" in prefer.lower():
            async def _bg():
                try:
                    await ensure_local(reg_m, name, ref)
                except Exception:
                    # La gestion d'erreur est déjà stockée dans 'inflight'
                    pass

            asyncio.create_task(_bg())
            status_url = f"/ensure-status/{reg_m}/{name}/{ref}"
            return Response(status_code=202, headers={"Location": status_url, "Retry-After": "2"})

        # Mode sync (HEAD/GET)
        try:
            digest = await ensure_local(reg_m, name, ref)
        except Exception as e:
            return Response(str(e), status_code=502)

        # Proxy vers le tampon
        # - HEAD: on garde {ref} pour le cas où un client head un tag (Docker-Content-Digest suit).
        # - GET: on peut renvoyer par digest pour stabilité.
        target_ref = ref if request.method == "HEAD" else digest
        url = f"{REG_LOCAL_BASE_URL}/v2/{reg_m}/{name}/manifests/{target_ref}"
        async with httpx.AsyncClient(timeout=None, verify=False) as client:
            upstream = await client.request(
                request.method, url, headers={"Accept": request.headers.get("accept", "*/*")}
            )
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=dict(upstream.headers),
        )

    # Blobs: simple proxy pass vers le tampon (le manifest ensure aura peuplé les blobs)
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
