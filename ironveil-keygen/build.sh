#!/usr/bin/env bash
# Build IronVeil Keygen for Windows (amd64 and arm64) from Linux or macOS.
# Runs the checks first, then writes the executables and SHA256SUMS.txt to dist/.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-1.0.0}"
export CGO_ENABLED=0

gofmt_out="$(gofmt -l .)"
if [ -n "$gofmt_out" ]; then
	echo "gofmt needed on:"; echo "$gofmt_out"; exit 1
fi
go vet ./...
GOOS=windows go vet ./...
go test -count=1 ./...

mkdir -p dist
rm -f dist/IronVeil-Keygen-*.exe dist/SHA256SUMS.txt
for arch in amd64 arm64; do
	GOOS=windows GOARCH="$arch" go build -trimpath -buildvcs=false \
		-ldflags "-s -w -H windowsgui -X main.version=${VERSION}" \
		-o "dist/IronVeil-Keygen-${VERSION}-windows-${arch}.exe" ./cmd/ironveil-keygen
done
(cd dist && sha256sum IronVeil-Keygen-*.exe > SHA256SUMS.txt && cat SHA256SUMS.txt)
