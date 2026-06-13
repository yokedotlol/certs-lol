#!/usr/bin/env bash
# Install certs CLI — curl -sSL https://certs.lol/install.sh | bash
set -euo pipefail

REPO="yokedotlol/certs-lol"

echo "Installing certs..."

# Detect OS/arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Get latest release tag
LATEST=$(curl -sfL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
if [ -z "$LATEST" ]; then
  echo "error: could not determine latest release" >&2; exit 1
fi

echo "  Version: $LATEST ($OS/$ARCH)"

# Build download URL
EXT="tar.gz"
[ "$OS" = "windows" ] && EXT="zip"
URL="https://github.com/$REPO/releases/download/$LATEST/certs_${OS}_${ARCH}.${EXT}"

# Pick install dir
if [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
elif [ -d "$HOME/.local/bin" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  mkdir -p "$HOME/.local/bin"
  INSTALL_DIR="$HOME/.local/bin"
fi

# Download and extract
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "  Downloading from GitHub Releases..."
curl -sfL -o "$TMP/certs.$EXT" "$URL" || {
  echo "error: download failed — $URL" >&2; exit 1
}

if [ "$EXT" = "tar.gz" ]; then
  tar -xzf "$TMP/certs.$EXT" -C "$TMP"
else
  unzip -q "$TMP/certs.$EXT" -d "$TMP"
fi

# Install binary
cp "$TMP/certs" "$INSTALL_DIR/certs"
chmod +x "$INSTALL_DIR/certs"

echo "  ✓ Installed to $INSTALL_DIR/certs"

# Verify
if "$INSTALL_DIR/certs" version &>/dev/null; then
  echo "  $($INSTALL_DIR/certs version)"
fi

# Check PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "  Add to your PATH:"
  echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo ""
echo "  Try it: certs example.com"
