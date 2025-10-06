import os, time, subprocess, shutil
import requests
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend

PROXY_BASE = os.getenv("PROXY_BASE", "https://localhost:8000")
VERIFY = os.getenv("TLS_VERIFY", "false").lower() in ("1","true","yes")

def run(cmd):
    print("[cmd]", " ".join(cmd))
    subprocess.check_call(cmd)

@pytest.mark.integration
def test_proxy_is_up():
    r = requests.get(f"{PROXY_BASE}/healthz", verify=VERIFY)
    assert r.status_code == 200
    r = requests.get(f"{PROXY_BASE}/v2/", verify=VERIFY)
    assert r.status_code == 200

@pytest.mark.integration
def test_ca_endpoint_available_and_valid():
    """Teste que le /ca retourne un certificat PEM valide"""
    r = requests.get(f"{PROXY_BASE}/ca", verify=False, timeout=5)
    assert r.status_code == 200, f"/ca returned {r.status_code}"
    assert b"-----BEGIN CERTIFICATE-----" in r.content, "Not a PEM format CA"
    # Vérifie qu'on peut parser le certificat
    try:
        cert = x509.load_pem_x509_certificate(r.content, default_backend())
        assert cert.subject is not None
        print("CA Subject:", cert.subject)
    except Exception as e:
        pytest.fail(f"Invalid PEM certificate: {e}")

@pytest.mark.integration
def test_push_then_pull_busybox():
    repo = "library/busybox"
    tag = "itestpush"

    # push via proxy -> tampon
    run([
        "skopeo","copy","--retry-times","3",
        "docker://docker.io/library/busybox:latest",
        f"docker://localhost:8000/{repo}:{tag}",
        "--dest-tls-verify=false"
    ])

    # wait ready using ensure-status (poll 45s max)
    status_url = f"{PROXY_BASE}/ensure-status/{repo.split('/')[0]}/{repo.split('/')[1]}/{tag}"
    deadline = time.time() + 45
    while time.time() < deadline:
        r = requests.get(status_url, verify=VERIFY, timeout=5)
        if r.status_code == 200:
            break
        elif r.status_code == 202:
            time.sleep(int(r.headers.get("Retry-After","1")))
        else:
            time.sleep(1)
    else:
        raise AssertionError("Prefetch (push) not ready in time")

    # pull via proxy (should hit cache)
    outdir = "/tmp/proxy-pull-itestpush"
    shutil.rmtree(outdir, ignore_errors=True)
    run([
        "skopeo","copy","--retry-times","3","--src-tls-verify=false",
        f"docker://localhost:8000/{repo}:{tag}",
        f"dir:{outdir}"
    ])

@pytest.mark.integration
def test_prefetch_status_async():
    repo = "library/busybox"
    tag = "latest"

    r = requests.get(f"{PROXY_BASE}/v2/{repo}/manifests/{tag}?async=1", verify=False, headers={"Prefer":"respond-async"})
    assert r.status_code == 202

    status_url = f"{PROXY_BASE}/ensure-status/{repo.split('/')[0]}/{repo.split('/')[1]}/{tag}"
    deadline = time.time() + 45
    while time.time() < deadline:
        r = requests.get(status_url, verify=False, timeout=5)
        if r.status_code == 200:
            return
        elif r.status_code == 202:
            time.sleep(int(r.headers.get("Retry-After","1")))
        else:
            time.sleep(1)
    raise AssertionError("Async ensure not ready in time")
