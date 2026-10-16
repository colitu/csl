#!/bin/sh
# Builds the colitu-engine sidecar for every app platform into engine/dist/.
# Pure Go (CGO_ENABLED=0): no C toolchain, one static binary per target.
# Android runs a linux binary shipped as lib<name>.so in the APK's native
# library directory (the only place an app may execute files from).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/dist"
mkdir -p "$out"
build() {
	echo "$1/$2 -> $3"
	(cd "$here/.." && CGO_ENABLED=0 GOOS=$1 GOARCH=$2 GOARM=${4:-7} go build -trimpath -ldflags "-s -w -buildid=" -o "$out/$3" ./engine/cmd/colitu-engine)
}
build windows amd64 windows-amd64/colitu-engine.exe
build windows arm64 windows-arm64/colitu-engine.exe
build linux amd64 linux-amd64/colitu-engine
build linux arm64 linux-arm64/colitu-engine
build linux arm64 android/arm64-v8a/libcolituengine.so
build linux arm android/armeabi-v7a/libcolituengine.so 7
build linux amd64 android/x86_64/libcolituengine.so
build linux 386 android/x86/libcolituengine.so
(cd "$out" && find . -type f | sort | xargs sha256sum > SHA256SUMS)
