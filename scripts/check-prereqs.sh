#!/usr/bin/env sh
# Verify the pubky-swap toolchain, then build + unit-test the workspace.
# Usage: ./scripts/check-prereqs.sh
set -eu

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }

echo "Checking prerequisites..."

missing=0
if command -v cargo >/dev/null 2>&1; then
  ok "cargo  ($(cargo --version))"
else
  err "cargo not found — install Rust from https://rustup.rs"
  missing=1
fi

if command -v rustc >/dev/null 2>&1; then
  ok "rustc  ($(rustc --version))"
else
  err "rustc not found — install Rust from https://rustup.rs"
  missing=1
fi

if command -v protoc >/dev/null 2>&1; then
  ok "protoc ($(protoc --version)) — the 'lnd' feature can be built"
else
  warn "protoc not found — only needed for the 'lnd' feature"
  warn "  install: brew install protobuf  |  apt install protobuf-compiler"
fi

if [ "$missing" -ne 0 ]; then
  echo
  err "Missing required tools; fix the above and re-run."
  exit 1
fi

echo
echo "Building the workspace (default features)..."
cargo build --all

echo
echo "Running unit tests..."
cargo test --all

cat <<'EOF'

All set. Next steps:

  • Try the negotiation demo (no Bitcoin/LN node needed) — see "Quickstart" in README.md
  • Run a full reverse swap on regtest with --features full — needs Polar (bitcoind + electrs + LND)
  • Integration tests are #[ignore]d; see CONTRIBUTING.md to run them
EOF
