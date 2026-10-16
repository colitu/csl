#!/bin/sh
# Copies the shared Adaptive Connect test vectors into the app repositories
# (their tests read their own copy). Run from anywhere; the app repos are
# expected next to this repo: ../colitu-android, ../colitu-windows, ...
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
src="$here/testdata/ac-vectors"
copy() {
	[ -d "$root/$1" ] || { echo "skip $1 (not found)"; return; }
	mkdir -p "$root/$2"
	cp "$src"/*.json "$root/$2/"
	echo "copied to $2"
}
copy colitu-android colitu-android/android/app/src/test/resources/ac-vectors
copy colitu-windows colitu-windows/src/ColituVPN.Tests/TestData/ac-vectors
copy colitu-linux colitu-linux/src/ColituVPN.Tests/TestData/ac-vectors
copy colitu-ios colitu-ios/test/ac-vectors
