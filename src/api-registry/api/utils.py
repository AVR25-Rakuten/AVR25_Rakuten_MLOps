import os
import json
import subprocess
import platform
import time
import httpx
import re

# Base URL du registry tampon (interne)
REG_LOCAL_BASE_URL = os.getenv("REG_LOCAL_BASE_URL", "http://internal-registry:5000")
# Hôte/port du registry tampon pour skopeo
TAMPON_REGISTRY = os.getenv("TAMPON_REGISTRY", "internal-registry:5000")

# Registry amont par défaut (si le chemin demandé ne contient pas de domaine)
UPSTREAM_REGISTRY = os.getenv("UPSTREAM_REGISTRY", "docker.io")

# TLS / proxies
INSECURE_SRC = os.getenv("INSECURE_SRC", "false").lower() in ("1", "true", "yes")
INSECURE_DEST = os.getenv("INSECURE_DEST", "true").lower() in ("1", "true", "yes")

# Mirroring: single-arch rapide par défaut, all-arch optionnel
MIRROR_ALL_ARCHS = os.getenv("MIRROR_ALL_ARCHS", "false").lower() in ("1", "true", "yes")
PLATFORM_OS = os.getenv("PLATFORM_OS", "linux")
PLATFORM_ARCH = os.getenv("PLATFORM_ARCH", "").lower()   # "amd64", "arm64", ...
PLATFORM_VARIANT = os.getenv("PLATFORM_VARIANT", "")     # ex "v7" pour arm 32 bits

# Retries réseau (timeouts, EOF, i/o timeout, handshake timeout…)
SKOPEO_RETRIES = int(os.getenv("SKOPEO_RETRIES", "6"))
SKOPEO_BACKOFF_BASE = float(os.getenv("SKOPEO_BACKOFF_BASE", "0.8"))  # secondes

_MANIFEST_ACCEPT = (
    "application/vnd.docker.distribution.manifest.v2+json,"
    "application/vnd.docker.distribution.manifest.list.v2+json,"
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.oci.image.manifest.v1+json,"
    "application/json"
)

_TRANSIENT_ERR_SNIPPETS = (
    "tls handshake timeout",
    "handshake timeout",
    "i/o timeout",
    "client.timeout exceeded",
    "connection timed out",
    "temporary failure",
    "connection reset",
    "unexpected eof",
    "eof",
    "proxy",
)

def _norm_arch(x: str) -> str:
    x = x.lower()
    return {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm", "armv6l": "arm"}.get(x, x)

def _has_domain(ns: str) -> bool:
    """Détecte si 'ns' ressemble à un host (docker.io, ghcr.io, quay.io, localhost:5000, ...)."""
    return "." in ns or ":" in ns or ns == "localhost"

def _compose_upstream_tag(reg: str, name: str, ref: str) -> str:
    """
    Construit 'host/namespace/name:tag' pour l’amont.
    Si 'reg' ne contient pas de domaine, on préfixe UPSTREAM_REGISTRY (docker.io par défaut).
    """
    host_ns = f"{reg}/{name}" if _has_domain(reg) else f"{UPSTREAM_REGISTRY}/{reg}/{name}"
    return f"{host_ns}:{ref}"

def _compose_upstream_digest(reg: str, name: str, digest: str) -> str:
    """
    Construit 'host/namespace/name@sha256:...' pour l’amont.
    """
    host_ns = f"{reg}/{name}" if _has_domain(reg) else f"{UPSTREAM_REGISTRY}/{reg}/{name}"
    return f"{host_ns}@{digest}"

def _tls_flags(src: bool = False, dest: bool = False) -> list[str]:
    flags: list[str] = []
    if src and INSECURE_SRC:
        flags += ["--src-tls-verify=false"]
    if dest and INSECURE_DEST:
        flags += ["--dest-tls-verify=false"]
    return flags

def _run_skopeo(args: list[str]) -> str:
    """
    Lance skopeo avec retries exponentiels sur erreurs transitoires réseau.
    Retourne stdout (str) si OK, sinon relance puis finit par propager l’exception.
    """
    attempt = 0
    last_err = None
    while attempt < SKOPEO_RETRIES:
        try:
            return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            out = e.output or str(e)
            if any(snip in out.lower() for snip in _TRANSIENT_ERR_SNIPPETS):
                last_err = out
                delay = SKOPEO_BACKOFF_BASE * (2 ** attempt)
                time.sleep(delay)
                attempt += 1
                continue
            raise
        except Exception as e:
            last_err = str(e)
            delay = SKOPEO_BACKOFF_BASE * (2 ** attempt)
            time.sleep(delay)
            attempt += 1
            continue
    if last_err:
        raise RuntimeError(f"skopeo retried {SKOPEO_RETRIES} times and still failed: {last_err}")
    raise RuntimeError(f"skopeo failed after {SKOPEO_RETRIES} attempts")

def _is_manifest_list_src(src_ref: str) -> bool:
    """
    Détermine si la source (docker://…) est un manifest list / OCI index.
    Utilise `skopeo inspect --raw` et détecte la présence de 'manifests' dans le JSON.
    """
    cmd = ["skopeo", "inspect", "--raw"]
    if INSECURE_SRC:
        cmd += ["--tls-verify=false"]
    cmd += [f"docker://{src_ref}"]
    raw = _run_skopeo(cmd)
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "manifests" in data:
            return True
        mt = data.get("mediaType") or ""
        return ("manifest.list" in mt) or ("image.index" in mt)
    except Exception:
        # fallback simple si pas JSON "propre"
        return "manifests" in raw

def _platform_overrides() -> list[str]:
    if MIRROR_ALL_ARCHS:
        return ["--all"]
    arch = PLATFORM_ARCH or _norm_arch(platform.machine())
    flags = [f"--override-os={PLATFORM_OS}", f"--override-arch={arch}"]
    if PLATFORM_VARIANT:
        flags.append(f"--override-variant={PLATFORM_VARIANT}")
    return flags

def _synth_tag_from_digest(digest: str) -> str:
    """
    Génère un tag sûr à partir d’un digest. Ex: sha256:abc… -> bydigest-sha256-abc…
    (max ~120 char pour rester confortable côté registry)
    """
    t = digest.replace(":", "-")
    if len(t) > 120:
        t = t[:120]
    return f"bydigest-{t}"

def skopeo_inspect_digest(ref: str) -> str:
    """
    Retourne le digest du manifest (tag ou digest) depuis la source publique.
    ref: 'host/ns/name:tag' (sans docker://)
    """
    cmd = ["skopeo", "inspect", "--retry-times", "3"]
    if INSECURE_SRC:
        cmd += ["--tls-verify=false"]
    cmd += [f"docker://{ref}"]
    out = _run_skopeo(cmd)
    data = json.loads(out)
    digest = data.get("Digest")
    if not digest:
        raise RuntimeError(f"Digest not found for {ref}")
    return digest

async def local_has_manifest(reg: str, name: str, digest: str) -> bool:
    """
    Vérifie la présence locale (tampon) d’un manifest par digest.
    """
    url = f"{REG_LOCAL_BASE_URL}/v2/{reg}/{name}/manifests/{digest}"
    async with httpx.AsyncClient(timeout=None) as client:
        r = await client.head(url, headers={"Accept": _MANIFEST_ACCEPT})
    return r.status_code == 200 and bool(r.headers.get("Docker-Content-Digest"))

def copy_to_local_digest(reg: str, name: str, digest: str) -> None:
    """
    Copie une référence source par DIGEST vers le registry tampon **en TAG** (jamais en @sha).
    - Si la source est un manifest list: copie --all (si MIRROR_ALL_ARCHS) ou force la plate-forme.
    - Le tag destination est synthétique et dérivé du digest (stable/idempotent).
    """
    src_ref = _compose_upstream_digest(reg, name, digest)  # host/ns/name@sha256:...
    dest_tag = _synth_tag_from_digest(digest)
    src = f"docker://{src_ref}"
    dest = f"docker://{TAMPON_REGISTRY}/{reg}/{name}:{dest_tag}"

    base = ["skopeo", "copy", "--retry-times", "3"] + _tls_flags(src=True, dest=True)
    is_index = False
    try:
        is_index = _is_manifest_list_src(src_ref)
    except Exception:
        # Si on n'arrive pas à déterminer, on tente copie simple (puis fallback plate-forme au besoin)
        is_index = False

    if is_index:
        cmd = base + _platform_overrides() + [src, dest]
    else:
        cmd = base + [src, dest]

    _run_skopeo(cmd)

def copy_to_local_tag(reg: str, name: str, ref: str) -> None:
    """
    Copie par TAG.
      - MIRROR_ALL_ARCHS=true  -> --all (manifest list + variantes)
      - sinon (défaut)         -> single-arch via --override-os/--override-arch[/--override-variant]
    """
    src_ref = _compose_upstream_tag(reg, name, ref)  # host/ns/name:tag
    src = f"docker://{src_ref}"
    dest = f"docker://{TAMPON_REGISTRY}/{reg}/{name}:{ref}"

    base = ["skopeo", "copy", "--retry-times", "3"] + _tls_flags(src=True, dest=True)

    # Détecte manifest list pour décider --all / overrides
    is_index = False
    try:
        is_index = _is_manifest_list_src(src_ref)
    except Exception:
        is_index = False

    if is_index:
        cmd = base + _platform_overrides() + [src, dest]
    else:
        if MIRROR_ALL_ARCHS:
            cmd = base + ["--all", src, dest]
        else:
            cmd = base + _platform_overrides() + [src, dest]

    _run_skopeo(cmd)
