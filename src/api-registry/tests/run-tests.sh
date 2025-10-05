#!/usr/bin/env bash
set -euo pipefail
cd /opt/tests
echo "[tests] Running pytest in $(pwd)..."
pytest -q -m "integration" -s