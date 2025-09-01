#!/usr/bin/env bash
# After using a lot of tools for scan and crawl .map and .js files without the 
# expected results, I decided to code my own tool using other tools from 
# projectdiscovery like katana and httpx. Ready? Who wanna be a cowboy? [;
#
# Overview:
# Crawl JS and pull SourceMaps across in-scope hosts using Katana + httpx + curl.
# Safe for testing with low rate limits and NO form submissions.

#  Requirements: 
#  katana
#  httpx
#  jq
#  curl
#  python
#
# Usage:
#   ./cartograph3r.sh <hosts file> <output directory to be created>
#   
#
# What it does:
#  1) Normalizes hosts to live base URLs with httpx (prefers HTTPS).
#  2) Crawls with Katana to discover JS files (depth 4, JS parsing enabled).
#  3) Filters only live JS URLs and downloads them.
#  4) Extracts and resolves sourceMappingURL for each JS and downloads the .map.


printf "  ____           _                              _     _____          \r\n"
printf " / ___|__ _ _ __| |_ ___   __ _ _ __ __ _ _ __ | |__ |___ / _ __     \r\n"
printf "| |   / _' | '__| __/ _ \ / _' | '__/ _' | '_ \| '_ \  |_ \| '__|    \r\n"
printf "| |__| (_| | |  | || (_) | (_| | | | (_| | |_) | | | |___) | |       \r\n"
printf " \____\__,_|_|   \__\___/ \__, |_|  \__,_| .__/|_| |_|____/|_|       \r\n"
printf "                          |___/          |_|                         \r\n"
printf "                                                                     \r\n"
			  
set -euo pipefail

export HOME

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <hosts_file> <outdir>"
  exit 1
fi

HOSTS_FILE="$1"
OUTDIR="$2"

mkdir -p $OUTDIR/{tmp,urls,js,maps,sources,logs}

#In case of crash, show line error
trap 'echo "[!] Error on line $LINENO: $BASH_COMMAND" >&2' ERR

$HOME/go/bin/./httpx -list $HOSTS_FILE -silent -no-color -fhr -p 443,80 > "$OUTDIR/tmp/base_urls.txt" 2> "$OUTDIR/logs/httpx_normalize.err"

# bail early if nothing was produced
if [ ! -s "$OUTDIR/tmp/base_urls.txt" ]; then
  echo "[!] httpx produced no base URLs. See $OUTDIR/logs/httpx_normalize.err" >&2
  exit 1
fi

# ensure the file exists so the sanitize step never fails even before katana runs
: > "$OUTDIR/urls/js_urls.txt"

python3 - "$OUTDIR/urls/js_urls.txt" > "$OUTDIR/urls/js_urls_sanitized.txt" <<'PY'
import sys, urllib.parse, pathlib
inp = pathlib.Path(sys.argv[1]).read_text().splitlines()
out = []
for u in inp:
    u = u.strip().rstrip("\r")
    if not u.startswith(("http://","https://")):
        continue
    p = urllib.parse.urlsplit(u)
    # encode path only (avoid double-encoding query/fragment)
    path = p.path.replace('[','%5B').replace(']','%5D').replace(' ','%20')
    out.append(urllib.parse.urlunsplit((p.scheme,p.netloc,path,p.query,p.fragment)))
print("\n".join(out))
PY

echo "[*] Checking which JS URLs are alive with httpx ..."
if [ ! -s "$OUTDIR/urls/js_urls_sanitized.txt" ]; then
  echo "[*] No JS URLs discovered by Katana — skipping alive check."
  : > "$OUTDIR/urls/js_urls_alive.txt"
else
  $HOME/go/bin/./httpx  -silent -no-color -fhr -mc 200  < "$OUTDIR/urls/js_urls_sanitized.txt"  > "$OUTDIR/urls/js_urls_alive.txt" 2> "$OUTDIR/logs/httpx_alive.err"
fi

grep -vE '/chunks/pages/.*\[[^]]+\]' "$OUTDIR/urls/js_urls_sanitized.txt"  > "$OUTDIR/urls/js_urls_sanitized.txt.tmp" && mv "$OUTDIR/urls/js_urls_sanitized.txt.tmp" "$OUTDIR/urls/js_urls_sanitized.txt"

echo "[*] Crawling with Katana to collect JS URLs (depth=4, js-crawl + jsluice, known-files)..."
$HOME/go/bin/./katana -list "$OUTDIR/tmp/base_urls.txt" -d 4 -jc -jsl -kf all -iqp -c 5 -p 5 -rlm 180 \
  -mr '.*\.js(\?.*)?$' -silent -o "$OUTDIR/urls/js_urls_raw.txt" || true

[ -f "$OUTDIR/urls/js_urls_raw.txt" ] || : > "$OUTDIR/urls/js_urls_raw.txt"

# Dedupe and basic sanity)
sort -u "$OUTDIR/urls/js_urls_raw.txt" > "$OUTDIR/urls/js_urls.txt"

# Sanitize again after js_urls.txt creation
python3 - "$OUTDIR/urls/js_urls.txt" > "$OUTDIR/urls/js_urls_sanitized.txt" <<'PY'
import sys, urllib.parse, pathlib
inp = pathlib.Path(sys.argv[1]).read_text().splitlines()
out = []
for u in inp:
    u = u.strip().rstrip("\r")
    if not u.startswith(("http://","https://")):
        continue
    p = urllib.parse.urlsplit(u)
    path = p.path.replace('[','%5B').replace(']','%5D').replace(' ','%20')
    out.append(urllib.parse.urlunsplit((p.scheme,p.netloc,path,p.query,p.fragment)))
print("\n".join(out))
PY

# Drop dev-style Next.js dynamic chunks
grep -vE '/chunks/pages/.*\[[^]]+\]' "$OUTDIR/urls/js_urls_sanitized.txt"  > "$OUTDIR/urls/js_urls_sanitized.txt.tmp" && mv "$OUTDIR/urls/js_urls_sanitized.txt.tmp" "$OUTDIR/urls/js_urls_sanitized.txt"

echo "[*] Checking which JS URLs are alive with httpx ..."
$HOME/go/bin/./httpx -silent -no-color -fhr -sc < "$OUTDIR/urls/js_urls_sanitized.txt" | awk '$2=="[200]" || $2==200 {print $1}' > "$OUTDIR/urls/js_urls_alive.txt"

echo "[*] Downloading JS files ..."
> "$OUTDIR/tmp/js_url_map.tsv"
: > "$OUTDIR/logs/js_download_errors.log"

while IFS= read -r url; do
  # keep only real http(s) URLs and strip stray CR/whitespace
  url="${url%%$'\r'*}"
  case "$url" in
    http://*|https://*) ;;
    *) continue ;;
  esac

  # Produce 3 lines (URL \n HOST \n FILENAME) and read them atomically
  mapfile -t triple < <(python3 - "$url" <<'PY'
import sys, urllib.parse, hashlib
u = sys.argv[1].strip()
p = urllib.parse.urlparse(u)
h = p.hostname or 'unknown-host'
fn = f"{hashlib.sha256(u.encode()).hexdigest()[:16]}.js"
print(u)
print(h)
print(fn)
PY
)
  u="${triple[0]}"
  h="${triple[1]}"
  fn="${triple[2]}"

  # sanity check
  [[ "$u" == http*://* ]] || continue

  mkdir -p "$OUTDIR/js/$h"

curl_url="$(
  python3 - "$u" <<'PY'
import sys, urllib.parse
u = sys.argv[1].strip()
p = urllib.parse.urlsplit(u)
path = p.path.replace('[', '%5B').replace(']', '%5D').replace(' ', '%20')
# keep query/fragment as-is (don't double-encode)
print(urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, p.fragment)))
PY
)"

if curl -g --globoff -k --path-as-is -fsSL --compressed \
         --max-time 20 --connect-timeout 10 \
         "$curl_url" -o "$OUTDIR/js/$h/$fn"; then
  printf '%s\t%s\t%s\n' "$u" "$h" "$fn" >> "$OUTDIR/tmp/js_url_map.tsv"
else
  echo "$u" >> "$OUTDIR/logs/js_download_errors.log"
fi

done < "$OUTDIR/urls/js_urls_alive.txt"

echo "[*] Extracting sourceMappingURL entries and resolving .map URLs ..."

JSMAP_TSV="$OUTDIR/tmp/js_url_map.tsv"
MAPLIST_TSV="$OUTDIR/tmp/map_url_map.tsv"
[ -f "$JSMAP_TSV" ] || : > "$JSMAP_TSV"
: > "$MAPLIST_TSV"

JS_DL_COUNT=$(wc -l < "$JSMAP_TSV" 2>/dev/null | tr -d ' ' || echo 0)
if [ "${JS_DL_COUNT:-0}" -eq 0 ]; then
  echo "[*] No JS files downloaded (js_url_map.tsv empty). Skipping extraction and moving on."
else
  while IFS=$'\t' read -r url host fn; do
    [ -n "$url" ] || continue
    js_path="$OUTDIR/js/$host/$fn"
    if [ ! -s "$js_path" ]; then
      echo "[*] Skipping missing/empty JS: $js_path" >> "$OUTDIR/logs/js_missing.log"
      continue
    fi

    # 1) Try inline sourceMappingURL comment
    map_url="$(
      python3 - <<'PY' "$js_path"
import sys, re, pathlib
p = pathlib.Path(sys.argv[1])
try:
    t = p.read_text('utf-8','replace').replace('\r','')
except Exception:
    sys.exit(0)
m = re.findall(r'(?:[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*)([^\s\*]+)', t, flags=re.IGNORECASE)
if m:
    print(m[-1].strip())
PY
)"
    map_url="$(
      python3 - <<'PY' "$js_path"
import sys, re, pathlib
p = pathlib.Path(sys.argv[1])
try:
    t = p.read_text('utf-8','replace').replace('\r','')
except Exception:
    sys.exit(0)
m = re.findall(r'sourceMappingURL=([^\s\*]+)', t)
if m:
    print(m[-1].strip())
PY
    )"

    # 2) If absent, probe HTTP headers for SourceMap or X-SourceMap
    if [ -z "$map_url" ]; then
      curl_hdr_url="$(
        python3 - "$url" <<'PY'
import sys, urllib.parse
u = sys.argv[1].strip()
p = urllib.parse.urlsplit(u)
path = p.path.replace('[','%5B').replace(']','%5D').replace(' ','%20')
print(urllib.parse.urlunsplit((p.scheme,p.netloc,path,p.query,p.fragment)))
PY
)"
      map_url="$(
        curl -g --globoff --path-as-is -k -fsSIL --max-time 12 --connect-timeout 8 "$curl_hdr_url" \
        | tr -d '\r' \
        | awk -F': *' 'tolower($1)=="sourcemap"||tolower($1)=="x-sourcemap"{print $2; exit}'
      )"
    fi

    if [ -n "$map_url" ]; then
      # Resolve relative -> absolute against the JS URL
      abs_url="$(
        python3 - <<'PY' "$url" "$map_url"
import sys, urllib.parse
base, rel = sys.argv[1], sys.argv[2]
print(urllib.parse.urljoin(base, rel))
PY
      )"
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$abs_url" "$host" "$(basename "$js_path").map" "$js_path" "DeclRef/Hdr" \
        >> "$MAPLIST_TSV"
      continue
    fi

    # 3) Heuristic(s) if nothing found: foo.js[?x] -> foo.js.map
    if [[ "$url" =~ \.js(\?.*)?$ ]]; then
      candidate="${url%%\?*}.map"          # typical foo.js.map
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$candidate" "$host" "$(basename "$js_path").map" "$js_path" "Heuristic" \
        >> "$MAPLIST_TSV"
    fi
  done < "$JSMAP_TSV"
fi

MAP_COUNT=$(wc -l < "$MAPLIST_TSV" 2>/dev/null | tr -d ' ' || echo 0)
echo "[*] Resolved $MAP_COUNT candidate .map URLs"

echo "[*] Downloading SourceMaps (.map) ..."
if [ "${MAP_COUNT:-0}" -eq 0 ]; then
  echo "[*] No .map candidates to download — skipping."
else
  while IFS=$'\t' read -r map_url host mapfn js_path how; do
    [ -n "$map_url" ] || continue
    mkdir -p "$OUTDIR/maps/$host"
    if [[ "$map_url" == data:* ]]; then
  python3 - <<'PY' "$map_url" "$OUTDIR/maps/$host/$mapfn"
import sys, re, base64, pathlib, urllib.parse
uri, out = sys.argv[1], sys.argv[2]

def decode_data_uri(u: str) -> bytes:
    if not u.startswith("data:"):
        raise ValueError("Not a data URI")
    header, payload = u.split(",", 1)
    # base64 or urlencoded?
    if ";base64" in header:
        s = re.sub(r"\s+", "", payload)            # strip whitespace/newlines
        s = s.replace("-", "+").replace("_", "/")  # urlsafe -> standard
        s += "=" * (-len(s) % 4)                   # fix padding
        return base64.b64decode(s)
    # urlencoded JSON/text
    return urllib.parse.unquote_to_bytes(payload)

pathlib.Path(out).write_bytes(decode_data_uri(uri))
PY
  continue
fi


curl_map_url="$(
  python3 - "$map_url" <<'PY'
import sys, urllib.parse
u = sys.argv[1].strip()
p = urllib.parse.urlsplit(u)
path = p.path.replace('[', '%5B').replace(']', '%5D').replace(' ', '%20')
print(urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, p.fragment)))
PY
)"

origin="$(
  python3 - "$curl_map_url" <<'PY'
import sys, urllib.parse
u=sys.argv[1].strip()
p=urllib.parse.urlsplit(u)
print(f"{p.scheme}://{p.netloc}/")
PY
)"

curl -k -g --globoff --path-as-is -kfsSL --compressed \
     -H "Referer: $origin" \
     -H "User-Agent: Mozilla/5.0" \
     --max-time 20 --connect-timeout 10 \
     "$curl_map_url" -o "$OUTDIR/maps/$host/$mapfn" \
  2>> "$OUTDIR/logs/map_download_errors.log" \
  || echo "$map_url" >> "$OUTDIR/logs/map_download_errors.log"


  done < "$MAPLIST_TSV"
fi


echo "[*] Done. Results:"
echo "  - JS URLs:     $OUTDIR/urls/js_urls_alive.txt"
echo "  - JS files:    $OUTDIR/js/"
echo "  - MAP files:   $OUTDIR/maps/"
echo "  - Sources:     $OUTDIR/sources/"

