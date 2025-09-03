#!/usr/bin/env bash

# cartograph3r.sh - JS & SourceMap reconnaissance engine (FIXED)
# Usage: ./cartograph3r.sh -t hosts.txt -o out/
#        ./cartograph3r.sh -t js_urls.txt -o out/ -u

set -euo pipefail

# Default values
OUTDIR="jsmap-out"
URLS_READY=false
HOSTS_FILE=""
HELP=false
RATE_LIMIT=0
HEADERS=()

# Function: apply_headers
apply_headers() {
  local extra_headers=()
  for hdr in "${HEADERS[@]}"; do
    extra_headers+=(-H "$hdr")
  done
  printf '%s ' "${extra_headers[@]}"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--target)
      HOSTS_FILE="$2"
      shift 2
      ;;
    -o|--output)
      OUTDIR="$2"
      shift 2
      ;;
    -u|--urls-ready)
      URLS_READY=true
      shift
      ;;
    -r|--rate-limit)
      if [[ "$2" =~ ^[0-9]+$ ]]; then
        RATE_LIMIT="$2"
        shift 2
      else
        echo "Error: Rate limit must be a number." >&2
        exit 1
      fi
      ;;
    -H|--header)
      HEADERS+=("$2")
      shift 2
      ;;
    -h|--help)
      HELP=true
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Help
if [[ "$HELP" == true ]]; then
  cat << 'EOF'
cartograph3r.sh - JS & SourceMap reconnaissance engine (HACKER-PROOF EDITION)

Usage:
  ./cartograph3r.sh -t <file> [OPTIONS]

Options:
  -t, --target <file>       Input file: hosts or JS URLs (with -u)
  -o, --output <dir>        Output directory (default: jsmap-out)
  -u, --urls-ready          Skip crawl, assume input has live JS URLs
  -r, --rate-limit <int>    Max requests per second
  -H, --header <string>     Add custom header (can be used multiple times)
  -h, --help                Show this help

Workflow:
  Full: hosts → katana → js_urls → download → .map
  URLs-ready: skip crawl, download JS → extract .map

Requirements:
  katana, httpx, curl, jq, python3

Example:
  ./cartograph3r.sh -t hosts.txt -o scan/
  ./cartograph3r.sh -t js_urls.txt -o scan/ -u \
    -H "Referer: https://crypto.com" \
    -H "User-Agent: Mozilla/5.0"
EOF
  exit 0
fi

# Validate input
if [[ -z "$HOSTS_FILE" ]]; then
  echo "Error: -t <target_file> is required." >&2
  exit 1
fi

if [[ ! -f "$HOSTS_FILE" ]]; then
  echo "Error: Target file '$HOSTS_FILE' not found." >&2
  exit 1
fi

# Create output structure
mkdir -p "$OUTDIR"/{tmp,urls,js,maps,sources,logs}

# On error, show line
trap 'echo "[!] Error on line $LINENO: $BASH_COMMAND" >&2' ERR

export HOME

# Banner
printf "  ____           _                              _     _____          \r\n"
printf " / ___|__ _ _ __| |_ ___   __ _ _ __ __ _ _ __ | |__ |___ / _ __     \r\n"
printf "| |   / _' | '__| __/ _ \\ / _' | '__/ _' | '_ \\| '_ \\  |_ \\| '__|    \r\n"
printf "| |__| (_| | |  | || (_) | (_| | | | (_| | |_) | | | |___) | |       \r\n"
printf " \\____\\__,_|_|   \\__\\___/ \\__, |_|  \\__,_| .__/|_| |_|____/|_|       \r\n"
printf "                          |___/          |_|                         \r\n"
printf "                                                                     \r\n"

echo "[*] Output directory: $OUTDIR"
echo "[*] Target file: $HOSTS_FILE"
if [[ "$URLS_READY" == true ]]; then
  echo "[*] Mode: URLs-ready (skipping crawl)"
else
  echo "[*] Mode: Full crawl (katana + httpx)"
fi

# Step 1: Normalize & crawl (if not URLs-ready)
if [[ "$URLS_READY" == false ]]; then
  echo "[*] Normalizing hosts to base URLs with httpx..."
  "$HOME"/go/bin/httpx -list "$HOSTS_FILE" -silent -no-color -fhr -p 443,80 > "$OUTDIR/tmp/base_urls.txt" 2> "$OUTDIR/logs/httpx_normalize.err"

  if [ ! -s "$OUTDIR/tmp/base_urls.txt" ]; then
    echo "[!] httpx produced no base URLs. See $OUTDIR/logs/httpx_normalize.err" >&2
    exit 1
  fi

  echo "[*] Crawling with Katana to collect JS URLs..."
  "$HOME"/go/bin/katana -list "$OUTDIR/tmp/base_urls.txt" \
    -d 4 -jc -jsl -kf all -iqp \
    -c 5 -p 5 -rlm 180 -timeout 30 \
    -mr '.*\.js(\?.*)?$' \
    -silent \
    -o "$OUTDIR/urls/js_urls_raw.txt" || true

  sort -u "$OUTDIR/urls/js_urls_raw.txt" > "$OUTDIR/urls/js_urls.txt"

  # Sanitize URLs
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

  # Filter Next.js chunks
  grep -vE '/chunks/pages/.*\[[^]]+\]' "$OUTDIR/urls/js_urls_sanitized.txt" > "$OUTDIR/urls/js_urls_sanitized.tmp" && mv "$OUTDIR/urls/js_urls_sanitized.tmp" "$OUTDIR/urls/js_urls_sanitized.txt"

  echo "[*] Checking which JS URLs are alive..."
  "$HOME"/go/bin/httpx -silent -no-color -fhr -sc < "$OUTDIR/urls/js_urls_sanitized.txt" | awk '$2=="[200]" || $2==200 {print $1}' > "$OUTDIR/urls/js_urls_alive.txt"
else
  # Use provided file as live JS URLs
  if [[ "$HOSTS_FILE" != "$OUTDIR/urls/js_urls_alive.txt" ]]; then
    cp "$HOSTS_FILE" "$OUTDIR/urls/js_urls_alive.txt"
    echo "[*] Copied JS URLs list."
  else
    echo "[*] Input is already in output dir — skipping copy."
  fi
  echo "[*] Using provided URLs as live JS list."
fi

# Step 2: Download JS files
echo "[*] Downloading JS files..."
> "$OUTDIR/tmp/js_url_map.tsv"
: > "$OUTDIR/logs/js_download_errors.log"

while IFS= read -r url; do
  url="${url%%$'\r'*}"
  case "$url" in
    http://*|https://*) ;;
    *) continue ;;
  esac

  # Extract host and hash-based filename
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

  [[ "$u" == http*://* ]] || continue
  mkdir -p "$OUTDIR/js/$h"

  # Fix encoded path
  curl_url="$(
    python3 - "$u" <<'PY'
import sys, urllib.parse
u = sys.argv[1].strip()
p = urllib.parse.urlsplit(u)
path = p.path.replace('[', '%5B').replace(']', '%5D').replace(' ', '%20')
print(urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, p.fragment)))
PY
  )"

  # Download with headers and rate limit
  if curl -g --globoff -k --path-as-is -fsSL --compressed \
       $(apply_headers) \
       --max-time 20 --connect-timeout 10 \
       "$curl_url" -o "$OUTDIR/js/$h/$fn"; then
    printf '%s\t%s\t%s\n' "$u" "$h" "$fn" >> "$OUTDIR/tmp/js_url_map.tsv"
    # Rate limit
    if [ "$RATE_LIMIT" -gt 0 ]; then
      sleep "$(awk "BEGIN {printf \"%.2f\", 1 / $RATE_LIMIT}")"
    fi
  else
    echo "$u" >> "$OUTDIR/logs/js_download_errors.log"
    echo "[*] Failed to download JS: $u"
  fi

done < "$OUTDIR/urls/js_urls_alive.txt"

# Step 3: Extract sourceMappingURL entries
echo "[*] Extracting sourceMappingURL entries..."
JSMAP_TSV="$OUTDIR/tmp/js_url_map.tsv"
MAPLIST_TSV="$OUTDIR/tmp/map_url_map.tsv"
: > "$MAPLIST_TSV"

if [ ! -s "$JSMAP_TSV" ]; then
  echo "[*] No JS files downloaded. Skipping .map extraction."
else
  while IFS=$'\t' read -r url host fn; do
    [ -n "$url" ] || continue
    js_path="$OUTDIR/js/$host/$fn"
    [ -s "$js_path" ] || continue

    # 1. Inline sourceMappingURL
    map_url="$(
      python3 - "$js_path" <<'PY'
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

    # 2. HTTP headers
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

      map_url=$( \
      curl -fsSL --http2 -L -D - -o /dev/null \
       -H 'Accept: */*' \
       -H 'Accept-Encoding: gzip, deflate, br' \
       -A 'Mozilla/5.0' "$curl_hdr_url" 2>/dev/null \
      | tr -d '\r' \
      | awk -F': *' 'tolower($1)=="sourcemap" || tolower($1)=="x-sourcemap" {print $2; exit}' \
      ) || map_url=""

    fi

    # 3. Resolve and save
    if [ -n "$map_url" ]; then
      abs_url=$(printf '%s\n%s' "$url" "$map_url" | bin/resolve_url.py)
      if [[ -n "$abs_url" && "$abs_url" =~ ^https?:// ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' \
          "$abs_url" "$host" "$(basename "$js_path").map" "$js_path" "DeclRef/Hdr" \
          >> "$MAPLIST_TSV"
      else
        echo "[*] Failed to resolve SourceMap URL: $map_url (from $url)" >> "$OUTDIR/logs/sourcemap_resolve_errors.log"
      fi
    elif [[ "$url" =~ \.js(\?.*)?$ ]]; then
      candidate="${url%%\?*}.map"
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$candidate" "$host" "$(basename "$js_path").map" "$js_path" "Heuristic" \
        >> "$MAPLIST_TSV"
    fi

  done < "$JSMAP_TSV"
fi

# Step 4: Download .map files
echo "[*] Resolved $(wc -l < "$MAPLIST_TSV" 2>/dev/null || echo 0) candidate .map URLs"

if [ ! -s "$MAPLIST_TSV" ]; then
  echo "[*] No .map candidates to download — skipping."
else
  echo "[*] Downloading SourceMaps..."
  while IFS=$'\t' read -r map_url host mapfn js_path how; do
    [ -n "$map_url" ] || continue
    mkdir -p "$OUTDIR/maps/$host"

    # Handle data: URI
    if [[ "$map_url" == data:* ]]; then
      python3 - "$map_url" "$OUTDIR/maps/$host/$mapfn" <<'PY'
import sys, re, base64, pathlib, urllib.parse
uri, out = sys.argv[1], sys.argv[2]
def decode_data_uri(u: str) -> bytes:
    if not u.startswith("data:"):
        raise ValueError("Not a data URI")
    header, payload = u.split(",", 1)
    if ";base64" in header:
        s = re.sub(r"\s+", "", payload)
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s)
    return urllib.parse.unquote_to_bytes(payload)
pathlib.Path(out).write_bytes(decode_data_uri(uri))
PY
      continue
    fi

    # Fix path for curl
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
u = sys.argv[1].strip()
p = urllib.parse.urlsplit(u)
print(f"{p.scheme}://{p.netloc}/")
PY
    )"

    # Download .map
    if curl -k -g --globoff --path-as-is -fsSL --compressed \
         -H "Referer: $origin" \
         $(apply_headers) \
         -H "User-Agent: Mozilla/5.0" \
         --max-time 20 --connect-timeout 10 \
         "$curl_map_url" -o "$OUTDIR/maps/$host/$mapfn"; then
      echo "[+] Downloaded: $map_url"
    else
      echo "[!] Failed: $map_url" >> "$OUTDIR/logs/map_download_errors.log"
    fi

    # Rate limit
    if [ "$RATE_LIMIT" -gt 0 ]; then
      sleep "$(awk "BEGIN {printf \"%.2f\", 1 / $RATE_LIMIT}")"
    fi

  done < "$MAPLIST_TSV"
fi

echo "[*] Done. Results:"
echo "  - JS URLs:     $OUTDIR/urls/js_urls_alive.txt"
echo "  - JS files:    $OUTDIR/js/"
echo "  - MAP files:   $OUTDIR/maps/"
echo "  - Sources:     $OUTDIR/sources/"
