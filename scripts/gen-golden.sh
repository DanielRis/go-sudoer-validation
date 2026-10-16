#!/bin/sh
# Regenerate testdata golden files from a real visudo(8).
#
# Each <case>.golden records `visudo -c` and `visudo -cs` results:
# the validity status and every diagnostic line, with the offending
# source line, caret marker, "Warning: " prefix and "parsed OK" removed.
#
# Usage: scripts/gen-golden.sh [visudo-binary]
set -eu

VISUDO=${1:-visudo}
cd "$(dirname "$0")/../testdata"

run() {
	dir=$1 name=$2 flags=$3
	if (cd "$dir" && "$VISUDO" $flags -f "$name" >/dev/null 2>&1); then
		echo "status: valid"
	else
		echo "status: invalid"
	fi
	(cd "$dir" && "$VISUDO" $flags -f "$name" 2>&1 || true) |
		sed -n -e 's/^Warning: //' -e "/^$name: parsed OK\$/d" \
		    -e "/^$name:/p" -e '/^visudo: /p'
}

for f in cases/*.sudoers regress/*.in; do
	dir=$(dirname "$f") name=$(basename "$f")
	{
		echo "[default]"
		run "$dir" "$name" -c
		echo "[strict]"
		run "$dir" "$name" -cs
	} >"${f%.*}.golden"
done
