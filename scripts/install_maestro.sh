#!/usr/bin/env bash
# Installs the Maestro CLI in ~/.maestro, at one version, from its GitHub release, and only
# when the archive has the SHA-256 written next to that version in the workflow.
# (The usual `curl get.maestro.mobile.dev | bash` runs whatever that address serves that day.)
# Env: MAESTRO_VERSION, MAESTRO_SHA256 (of maestro.zip in the release cli-<version>)
set -euo pipefail
VERSION=${MAESTRO_VERSION:?set MAESTRO_VERSION}
SHA=${MAESTRO_SHA256:?set MAESTRO_SHA256}
tmp=$(mktemp -d)
curl -fsSL --retry 3 -o "$tmp/maestro.zip" "https://github.com/mobile-dev-inc/maestro/releases/download/cli-$VERSION/maestro.zip"
got=$(shasum -a 256 "$tmp/maestro.zip" | cut -d' ' -f1)
if [ "$got" != "$SHA" ]; then
  echo "::error::Maestro $VERSION: the archive is not the one expected (SHA-256 $got). Nothing installed."
  exit 1
fi
unzip -q "$tmp/maestro.zip" -d "$tmp"
rm -rf "$HOME/.maestro"; mkdir -p "$HOME/.maestro"
cp -R "$tmp/maestro/." "$HOME/.maestro/"
rm -rf "$tmp"
[ -z "${GITHUB_PATH:-}" ] || echo "$HOME/.maestro/bin" >> "$GITHUB_PATH"
echo "Maestro $VERSION installed in $HOME/.maestro"
