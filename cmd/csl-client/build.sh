#!/bin/sh
# Builds the csl-client sidecar for the apps that run it into
# cmd/csl-client/dist/. Pure Go (CGO_ENABLED=0), one static binary per target.
# Android runs a linux binary shipped as libcslclient.so in the APK's native
# library directory (the only place an app may execute files from); it only
# talks to loopback (the core's carrier inbounds), so it needs no resolver.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/dist"
mkdir -p "$out"
build() {
	echo "$1/$2 -> $3"
	(cd "$here/../.." && CGO_ENABLED=0 GOOS=$1 GOARCH=$2 GOARM=${4:-7} go build -trimpath -ldflags "-s -w -buildid=" -o "$out/$3" ./cmd/csl-client)
}
build windows amd64 win-x64/csl-client.exe
build windows arm64 win-arm64/csl-client.exe
build linux arm64 android/arm64-v8a/libcslclient.so
build linux arm android/armeabi-v7a/libcslclient.so 7
build linux amd64 android/x86_64/libcslclient.so
build linux 386 android/x86/libcslclient.so
(cd "$out" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)
