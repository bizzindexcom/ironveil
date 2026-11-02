#!/usr/bin/env bash
# Rebuild checksums, run release checks, then zip.  Usage: package.sh [--dev] <plugin-dir> <out-dir>
set -euo pipefail
flag=(); [ "${1:-}" = "--dev" ] && { flag=(--dev); shift; }
dir="$(cd "${1:?plugin dir}" && pwd)"; out="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
[ "$(basename "$dir")" = "ironveil-security" ] || { echo "Folder must be named ironveil-security/"; exit 2; }
leak=$(find "$dir" \( -iname '*.key' -o -iname '*private*' -o -iname '*owner-kit*' -o -iname '*.pem' -o -name '.env' \) -print)
[ -z "$leak" ] || { echo "Refusing: secret-looking files in the plugin folder:"; echo "$leak"; exit 1; }
# 1.3.x: the checksum builder lives in ironveil-owner-tools/ next to the plugin (1.2.x: inside tools/).
builder="${IRONVEIL_OWNER_TOOLS:-$(dirname "$dir")/ironveil-owner-tools}/build-checksums.php"
[ -f "$builder" ] || builder="$dir/tools/build-checksums.php"
[ -f "$builder" ] || { echo "build-checksums.php not found; set IRONVEIL_OWNER_TOOLS=/path/to/ironveil-owner-tools"; exit 2; }
php "$builder" "$dir"
bash "$here/release_check.sh" ${flag[@]+"${flag[@]}"} "$dir"
ver=$(sed -n "s/^define( 'IRONVEIL_VERSION', '\([^']*\)' );/\1/p" "$dir/ironveil-security.php")
zip="$out/ironveil-security-$ver.zip"; rm -f "$zip"
(cd "$(dirname "$dir")" && zip -qrX "$zip" ironveil-security -x '*.DS_Store' '*/.git/*')
echo "Built $zip ($(unzip -l "$zip" | tail -1 | awk '{print $2}') files)"
