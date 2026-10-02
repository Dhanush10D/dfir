#!/usr/bin/env bash
# Security scans (Phase 10, guide 20.1 "supply chain", 21.2/21.3; docs/hardening.md). Needs network
# (advisory databases) and Docker. Reports and SBOMs go to var/scan/ (git-ignored).
#   bash scripts/scan.sh            # all scans
#   SCAN_SKIP_IMAGES=1 bash ...     # without the image scans (no built images)
# Gates (non-zero exit):
#   * gitleaks over the whole git history; reviewed non-secrets are baselined in .gitleaksignore;
#   * pip-audit over the backend's pinned dependency set (pip freeze of the venv: the app and its
#     dependencies; pip/setuptools tooling is not part of the shipped dependency set);
#   * npm audit --audit-level=high over the frontend lockfile;
#   * Trivy: CRITICAL vulnerabilities with a fix available in language packages of the api and
#     worker images. OS-package and HIGH findings are reported (var/scan/trivy-*.txt) without
#     failing: they are fixed by rebuilding on an updated base image (docs/hardening.md).
# Ignored advisories need an entry with a reason in .trivyignore / scripts/scan-ignore.txt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"  # C:/... in Git Bash, so it survives MSYS_NO_PATHCONV
OUT="$ROOT/var/scan"
mkdir -p "$OUT"
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"
TRIVY_IMAGE="aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"
PIP_AUDIT_VERSION="2.10.1"
CYCLONEDX_VERSION="7.5.0"
step() { printf '\n==> %s\n' "$*"; }
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
export MSYS_NO_PATHCONV=1

cd "$ROOT/backend"
if [[ -x .venv/Scripts/python ]]; then BIN=.venv/Scripts; else BIN=.venv/bin; fi
if [[ -x "$OUT/venv/Scripts/python" ]]; then SBIN="$OUT/venv/Scripts";
elif [[ -x "$OUT/venv/bin/python" ]]; then SBIN="$OUT/venv/bin";
else
  "$BIN/python" -m venv "$(winpath "$OUT/venv")"
  if [[ -x "$OUT/venv/Scripts/python" ]]; then SBIN="$OUT/venv/Scripts"; else SBIN="$OUT/venv/bin"; fi
fi
"$SBIN/python" -m pip install -q "pip-audit==$PIP_AUDIT_VERSION" "cyclonedx-bom==$CYCLONEDX_VERSION"

step "gitleaks: whole git history (baseline: .gitleaksignore)"
docker run --rm -v "$(winpath "$ROOT"):/repo" "$GITLEAKS_IMAGE" git /repo --redact --no-banner \
  --report-format json --report-path /repo/var/scan/gitleaks.json

step "pip-audit: backend dependency set (frozen from the venv)"
"$BIN/python" -m pip freeze --exclude-editable > "$OUT/backend-requirements.txt"
ignore_args=()
if [[ -f "$ROOT/scripts/scan-ignore.txt" ]]; then
  while read -r id _; do
    [[ -z "$id" || "$id" == \#* ]] && continue
    ignore_args+=(--ignore-vuln "$id")
  done < "$ROOT/scripts/scan-ignore.txt"
fi
"$SBIN/pip-audit" -r "$(winpath "$OUT/backend-requirements.txt")" --no-deps --progress-spinner off \
  ${ignore_args[@]+"${ignore_args[@]}"}
"$SBIN/cyclonedx-py" environment "$(winpath "$ROOT/backend/$BIN/python")" --output-format JSON \
  --output-file "$(winpath "$OUT/sbom-backend.cdx.json")"
echo "SBOM: var/scan/sbom-backend.cdx.json"

step "npm audit (high and critical) and SBOM: frontend"
cd "$ROOT/frontend"
npm audit --audit-level=high
npm sbom --sbom-format cyclonedx > "$OUT/sbom-frontend.cdx.json"
echo "SBOM: var/scan/sbom-frontend.cdx.json"

if [[ "${SCAN_SKIP_IMAGES:-0}" == "1" ]]; then
  step "image scans skipped (SCAN_SKIP_IMAGES=1)"
  exit 0
fi

step "Trivy: api and worker images (gate: fixable CRITICAL in language packages)"
docker volume create dfirbench-trivy-cache >/dev/null
for image in api worker; do
  tar="$OUT/$image.tar"
  docker save "dfirbench/$image:dev" -o "$(winpath "$tar")"
  run_trivy() {
    docker run --rm --network bridge -v dfirbench-trivy-cache:/root/.cache \
      -v "$(winpath "$OUT"):/scan" -v "$(winpath "$ROOT/.trivyignore"):/scan-ignore:ro" \
      "$TRIVY_IMAGE" image --input "/scan/$image.tar" --ignorefile /scan-ignore --quiet "$@"
  }
  run_trivy --scanners vuln --severity HIGH,CRITICAL --format table \
    --output "/scan/trivy-$image.txt"
  run_trivy --format cyclonedx --output "/scan/sbom-image-$image.cdx.json"
  run_trivy --scanners vuln --pkg-types library --severity CRITICAL --ignore-unfixed \
    --exit-code 1 --format table
  rm -f "$tar"
  echo "report: var/scan/trivy-$image.txt; SBOM: var/scan/sbom-image-$image.cdx.json"
done

step "SCANS PASSED"
