#!/usr/bin/env bash
# run-dev-ts.sh - v1.0.0 (2026-09-09)
# Start a Linux-only, local scitt-ccf-ledger and prepare a pyscitt fixture.
# Usage: scripts/run-dev-ts.sh [port] | scripts/run-dev-ts.sh --stop
# Install the matching CLI in a Python 3.12+ virtual environment:
# python3 -m pip install 'git+https://github.com/microsoft/scitt-ccf-ledger@bffdf529185ba7767db5f2cfc4c1898ec8ad3364#subdirectory=pyscitt'
set -euo pipefail

VERSION="1.0.0"
SCITT_REV="bffdf529185ba7767db5f2cfc4c1898ec8ad3364"
SCITT_IMAGE="pask-scitt-dev:${SCITT_REV}"
CONTAINER="scitt-dev"
OWNER_LABEL="io.wilder.pask.dev-ts"
CONTAINER_CREATED=0
STARTUP_COMPLETE=0

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Missing $1. $2"
}

# Only an exact 200 is ready. Each request and the overall wait are bounded.
# Kept independent of Docker so the polling can be exercised with a stub.
wait_for_service() {
  local url="$1" timeout="${2:-60}" deadline status
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    status=$(curl --noproxy '*' --silent --insecure --connect-timeout 1 \
      --max-time 2 --output /dev/null --write-out '%{http_code}' \
      "${url}/node/network") || status=000
    [[ "$status" == 200 ]] && return 0
    sleep 1
  done
  printf 'Service did not become healthy at %s within %s seconds.\n' "$url" "$timeout" >&2
  return 1
}

cleanup_failed_start() {
  local status=$?
  if (( CONTAINER_CREATED && ! STARTUP_COMPLETE )); then
    docker logs "$CONTAINER" >&2 || true
    docker stop "$CONTAINER" >/dev/null 2>&1 || true
    docker rm "$CONTAINER" >/dev/null 2>&1 || true
  fi
  return "$status"
}

stop_service() {
  if ! docker container inspect "$CONTAINER" >/dev/null 2>&1; then
    printf '%s is already stopped and removed.\n' "$CONTAINER"
    return
  fi
  [[ $(docker inspect --format "{{index .Config.Labels \"${OWNER_LABEL}\"}}" "$CONTAINER") == true ]] \
    || die "Container $CONTAINER was not created by this script."
  docker stop "$CONTAINER" >/dev/null
  docker rm "$CONTAINER" >/dev/null
  printf 'Stopped and removed %s. Development files are retained.\n' "$CONTAINER"
}

main() {
  (( EUID != 0 )) || die "Run as a regular user with access to Docker, not as root."
  (( $# <= 1 )) || die "Usage: $0 [port] | $0 --stop"
  require_command docker "Install Docker Engine and grant your user access to the daemon."
  docker info >/dev/null 2>&1 || die "Docker is not running or this user cannot access its daemon."
  if [[ ${1:-} == --stop ]]; then
    stop_service
    return
  fi

  local port="${1:-8000}" url state_dir source_dir node_dir fingerprint issuer
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "Port must be an integer from 1 to 65534."
  port=$((10#$port))
  (( port > 0 && port < 65535 )) || die "Port must be from 1 to 65534; the next port is used by CCF."
  [[ $(uname -s) == Linux ]] || die "This script requires Linux Docker host networking."
  require_command curl "Install curl with your distribution's package manager."
  require_command openssl "Install OpenSSL with your distribution's package manager."
  require_command python3 "Install Python 3.12 or newer."
  require_command tar "Install tar with your distribution's package manager."
  require_command git "Install Git with your distribution's package manager."
  require_command scitt "Activate your pyscitt virtual environment, or install the pinned CLI with: python3 -m pip install 'git+https://github.com/microsoft/scitt-ccf-ledger@${SCITT_REV}#subdirectory=pyscitt'"
  python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ is required"'
  scitt sign --help | grep -q -- --uses-cwt || die "The installed scitt CLI lacks --uses-cwt. Install the pinned version in this script's header."
  if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
    die "Container $CONTAINER already exists. Run $0 --stop first."
  fi

  umask 077
  state_dir="${PASK_TS_WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/pask-dev-ts.XXXXXX")}"
  [[ ! -L "$state_dir" ]] || die "The development directory must not be a symlink."
  [[ -d "$state_dir" ]] || mkdir -p "$state_dir"
  [[ -O "$state_dir" ]] || die "The development directory must belong to this user."
  chmod 700 "$state_dir"
  state_dir=$(cd "$state_dir" && pwd -P)
  source_dir="${PASK_SCITT_SOURCE:-${state_dir}/source}"
  if [[ -n ${PASK_SCITT_SOURCE:-} ]]; then
    [[ $(git -C "$source_dir" rev-parse HEAD) == "$SCITT_REV" ]] \
      || die "PASK_SCITT_SOURCE must be checked out at $SCITT_REV."
  else
    mkdir -p "$source_dir"
    curl --fail --location --show-error --silent \
      "https://codeload.github.com/microsoft/scitt-ccf-ledger/tar.gz/${SCITT_REV}" \
      | tar -xz --strip-components=1 -C "$source_dir"
  fi
  source_dir=$(cd "$source_dir" && pwd -P)

  # Upstream documents a source build, not a self-provisioning registry image.
  # CI loads this same pinned image using BuildKit's GitHub Actions cache.
  if ! docker image inspect "$SCITT_IMAGE" >/dev/null 2>&1; then
    DOCKER_BUILDKIT=1 docker build --tag "$SCITT_IMAGE" \
      --file "$source_dir/docker/Dockerfile" \
      --build-arg "SCITT_VERSION_OVERRIDE=$SCITT_REV" "$source_dir"
  fi

  cp -R "$source_dir/app/constitution" "$state_dir/"
  (
    cd "$state_dir"
    bash "$source_dir/docker/keygenerator.sh" --name member0 --gen-enc-key
  )
  node_dir=$(mktemp -d "${state_dir}/node.XXXXXX")
  python3 - "$source_dir/docker/dev-config.tmpl.json" "$state_dir/dev-config.json" "$port" "${node_dir##*/}" <<'PY'
import json
import sys
from pathlib import Path

source, destination, port, node = sys.argv[1:]
config = json.loads(Path(source).read_text().replace('%CCF_PORT%', port))
network = config['network']
network['node_to_node_interface']['bind_address'] = f'127.0.0.1:{int(port) + 1}'
for interface in network['rpc_interfaces'].values():
    interface['bind_address'] = f'127.0.0.1:{port}'
    interface['published_address'] = f'127.0.0.1:{port}'
config['node_certificate']['subject_alt_names'] = ['iPAddress:127.0.0.1', 'dNSName:localhost']
config['command']['service_certificate_file'] = f'/host/{node}/service_cert.pem'
Path(destination).write_text(json.dumps(config, indent=2))
PY

  trap cleanup_failed_start EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # Host networking keeps both CCF interfaces on loopback. Docker port
  # forwarding cannot reach a service bound to container-local loopback.
  docker run --name "$CONTAINER" --detach --init --network host \
    --label "${OWNER_LABEL}=true" --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=${state_dir},dst=/host" \
    --workdir "/host/${node_dir##*/}" --entrypoint cchost \
    "$SCITT_IMAGE" --config /host/dev-config.json --log-level info >/dev/null
  CONTAINER_CREATED=1
  url="https://127.0.0.1:${port}"
  wait_for_service "$url"
  scitt governance local_development --url "$url" \
    --member-key "$state_dir/member0_privk.pem" --member-cert "$state_dir/member0_cert.pem"
  # The service certificate is written into our private bind mount by CCF.
  # It contains the public key and is the TLS trust root used by the test.
  cp "$node_dir/service_cert.pem" "$state_dir/service_cert.pem"
  curl --noproxy '*' --fail --silent --show-error --max-time 10 \
    --cacert "$state_dir/service_cert.pem" "$url/node/network" \
    > "$state_dir/network.json"
  python3 - "$state_dir/network.json" <<'PY'
import json
import sys
from pathlib import Path
assert json.loads(Path(sys.argv[1]).read_text())['service_status'] == 'Open', 'Service is not open'
PY

  openssl genpkey -algorithm Ed25519 -out "$state_dir/issuer-key.pem"
  openssl req -new -x509 -key "$state_dir/issuer-key.pem" \
    -out "$state_dir/issuer-cert.pem" -days 365 -subj '/CN=pask-dev' \
    -addext 'extendedKeyUsage=codeSigning'
  # did:x509 uses an unpadded base64url digest, not a hex fingerprint.
  fingerprint=$(openssl x509 -in "$state_dir/issuer-cert.pem" -outform DER \
    | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  # This is the standard codeSigning EKU, matching the certificate above.
  issuer="did:x509:0:sha256:${fingerprint}::eku:1.3.6.1.5.5.7.3.3"
  printf '%s\n' '{"type":"Claim","name":"pask-ts-client dev test"}' > "$state_dir/statement.json"
  scitt sign --statement "$state_dir/statement.json" --key "$state_dir/issuer-key.pem" \
    --x5c "$state_dir/issuer-cert.pem" --content-type application/json \
    --issuer "$issuer" --out "$state_dir/signed-statement.cose" --uses-cwt

  # Plain assignments for GITHUB_ENV; shell-quoted exports for local users.
  printf 'PASK_TS_URL=%s\nPASK_SIGNED_STATEMENT_PATH=%s\nPASK_TS_SERVICE_KEY_PATH=%s\n' \
    "$url" "$state_dir/signed-statement.cose" "$state_dir/service_cert.pem" > "$state_dir/github.env"
  printf '\nrun-dev-ts.sh v%s: service ready at %s\n' "$VERSION" "$url"
  printf 'export PASK_TS_URL=%q\n' "$url"
  printf 'export PASK_SIGNED_STATEMENT_PATH=%q\n' "$state_dir/signed-statement.cose"
  printf 'export PASK_TS_SERVICE_KEY_PATH=%q\n' "$state_dir/service_cert.pem"
  printf 'Stop with: %s --stop\n' "$0"
  STARTUP_COMPLETE=1
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
