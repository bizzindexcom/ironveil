#!/usr/bin/env bash
# Release checks for an unpacked IronVeil plugin folder.
# Usage: release_check.sh [--dev] <plugin-dir> [expected-version]
# Builds are for distribution (wordpress.org) by default: placeholders fail. --dev turns them into warnings.
set -u
dev=0; [ "${1:-}" = "--dev" ] && { dev=1; shift; }
dir="${1:?plugin dir}"; want="${2:-}"
fail=0; warn=0
ok()   { echo "  ok    $1"; }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
note() { echo "  WARN  $1"; warn=$((warn+1)); }

main="$dir/ironveil-security.php"; readme="$dir/readme.txt"
[ -f "$main" ] && [ -f "$readme" ] || { echo "Not an IronVeil plugin folder: $dir"; exit 2; }

hdr=$(sed -n 's/^ \* Version: *//p' "$main" | tr -d '[:space:]')
def=$(sed -n "s/^define( 'IRONVEIL_VERSION', '\([^']*\)' );/\1/p" "$main")
tag=$(sed -n 's/^Stable tag: *//p' "$readme" | tr -d '[:space:]')
echo "Versions: header=$hdr define=$def stable_tag=$tag"
if [ "$hdr" = "$def" ] && [ "$def" = "$tag" ]; then ok "version consistent ($def)"; else bad "version mismatch"; fi
[ -z "$want" ] || [ "$def" = "$want" ] && ok "matches expected ${want:-(none given)}" || bad "expected $want, found $def"
grep -q "^= $def =" "$readme" && ok "readme changelog has = $def =" || bad "readme.txt has no '= $def =' changelog entry"

lint=0
while IFS= read -r f; do php -l "$f" >/dev/null 2>&1 || { bad "php -l $f"; lint=1; }; done < <(find "$dir" -name '*.php')
[ $lint -eq 0 ] && ok "php -l clean"

php -r '
$d=$argv[1]; $c=json_decode(@file_get_contents("$d/checksums.json"),true);
if(!$c){echo "  FAIL  checksums.json missing or invalid\n"; exit(1);}
$bad=0; foreach($c["files"] as $f=>$h){ if(!is_file("$d/$f")||md5_file("$d/$f")!==$h){echo "  FAIL  checksum $f\n";$bad++;} }
$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d,FilesystemIterator::SKIP_DOTS));
foreach($it as $f){$r=substr($f->getPathname(),strlen($d)+1); if($r!=="checksums.json"&&!isset($c["files"][$r])){echo "  FAIL  not in checksums.json: $r\n";$bad++;}}
if($c["version"]!==$argv[2]){echo "  FAIL  checksums.json version ".$c["version"]." != ".$argv[2]."\n";$bad++;}
if(!$bad) echo "  ok    checksums.json matches ".count($c["files"])." files\n";
exit(min($bad,200));' "$dir" "$def"; fail=$((fail+$?))

secrets=$(find "$dir" \( -iname '*.key' -o -iname '*private*' -o -iname '*owner-kit*' -o -iname '*.pem' -o -name '.env' \) -print)
[ -z "$secrets" ] && ok "no key/secret files" || bad "secret-looking files: $secrets"
grep -rlE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "$dir" >/dev/null && bad "PEM private key content found"
[ -f "$dir/tools/.htaccess" ] && ok "tools/.htaccess present" || bad "tools/.htaccess missing (CLI tools would be web-reachable)"

ph() { if [ $dev -eq 1 ]; then note "$1"; else bad "$1 (distribution build; use --dev for a test build)"; fi; }
grep -q "PURCHASE_URL = 'https://example.com" "$dir/includes/class-license.php" && ph "License::PURCHASE_URL is still the example.com placeholder"
grep -q "DEFAULT_FEED_URL = ''" "$dir/includes/class-license.php" && ph "License::DEFAULT_FEED_URL is empty"
grep -q "^ \* Plugin URI: *https://example.com" "$dir/ironveil-security.php" && ph "Plugin URI is still the example.com placeholder"

echo; if [ $fail -eq 0 ]; then echo "ALL CHECKS PASSED ($warn warning(s))"; else echo "$fail CHECK(S) FAILED"; fi
exit $([ $fail -eq 0 ] && echo 0 || echo 1)
