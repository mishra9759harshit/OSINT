#!/usr/bin/env bash
# osint_toolkit_advanced.sh
# Advanced, scalable passive OSINT toolkit (Termux / Linux)
# Usage examples:
#   ./osint_toolkit_advanced.sh --email someone@example.com
#   ./osint_toolkit_advanced.sh --phone "+919876543210" --install-deps
#   ./osint_toolkit_advanced.sh --domain example.com --concurrency 6 --outdir ./reports
#
# Notes:
# - Place API keys in a file named ".env" in same folder or export them in your shell.
#   Example .env:
#     HIBP_API_KEY="..."
#     HUNTER_API_KEY="..."
#     SHODAN_API_KEY="..."
#     NUMVERIFY_API_KEY="..."
#     EMAILREP_API_KEY="..."
#
# - This script performs passive lookups only. Active scans (nmap) require --enable-active
# - Use responsibly and obey local laws & terms of service.

set -euo pipefail
IFS=$'\n\t'

### -------------------------
### Defaults & config
### -------------------------
PROGNAME="$(basename "$0")"
DEFAULT_CONCURRENCY=4
DEFAULT_RATE=1     # seconds between rate-limited requests in each worker
TS=$(date +%Y%m%d_%H%M%S)
OUTDIR=""
CONCURRENCY=$DEFAULT_CONCURRENCY
RATE_LIMIT=$DEFAULT_RATE
ENABLE_ACTIVE=false
DO_INSTALL_DEPS=false
DO_CSV=true
DO_HTML=true

# Tools we rely on
REQUIRED_TOOLS=(curl jq git md5sum awk sed grep uname)
OPTIONAL_TOOLS=(whois dig nmap exiftool python3 pip)

### -------------------------
### Helpers & env load
### -------------------------
logfile=""
log() { printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$logfile"; }
err()  { printf '[%s] ERROR: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$logfile" >&2; }

# Load .env if present
if [ -f ".env" ]; then
  # shellcheck disable=SC1091
  set -o allexport; source .env; set +o allexport
fi

usage() {
  cat <<USAGE
$PROGNAME — Advanced OSINT toolkit

Usage:
  $PROGNAME [options] --email someone@example.com
  $PROGNAME [options] --phone "+919876543210"
  $PROGNAME [options] --domain example.com
  $PROGNAME [options] --username username

Options:
  --install-deps       Attempt to install missing packages automatically (requires sudo on some systems)
  --enable-active      Enable active scans (nmap) - only run if you have permission
  --concurrency N      Number of parallel workers (default: $DEFAULT_CONCURRENCY)
  --rate S             Rate limit (seconds) between requests per worker (default: $DEFAULT_RATE)
  --outdir DIR         Output directory (default: ./osint_<timestamp>)
  --no-csv             Do not generate CSV summary
  --no-html            Do not generate HTML summary
  --help               Show this message

USAGE
  exit 1
}

# detect package manager
detect_pkg_mgr() {
  if command -v pkg >/dev/null 2>&1; then echo "pkg"    # Termux
  elif command -v apt >/dev/null 2>&1; then echo "apt"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v apk >/dev/null 2>&1; then echo "apk"
  elif command -v yum >/dev/null 2>&1; then echo "yum"
  else echo "unknown"
  fi
}

# install missing packages (best-effort)
install_missing() {
  local pm; pm=$(detect_pkg_mgr)
  local to_install=("$@")
  if [ "$pm" = "unknown" ]; then
    err "Unknown package manager. Install packages manually: ${to_install[*]}"
    return 1
  fi

  case "$pm" in
    pkg)
      log "Using Termux pkg to install: ${to_install[*]}"
      pkg update -y || true
      pkg install -y "${to_install[@]}" || true
      ;;
    apt)
      log "Using apt to install: ${to_install[*]}"
      sudo apt update || true
      sudo apt install -y "${to_install[@]}" || true
      ;;
    pacman)
      log "Using pacman to install: ${to_install[*]}"
      sudo pacman -Syu --noconfirm "${to_install[@]}" || true
      ;;
    apk)
      log "Using apk to install: ${to_install[*]}"
      sudo apk update || true
      sudo apk add "${to_install[@]}" || true
      ;;
    yum)
      log "Using yum to install: ${to_install[*]}"
      sudo yum install -y "${to_install[@]}" || true
      ;;
    *)
      err "Unsupported package manager: $pm"
      ;;
  esac
}

# Ensure core deps are installed if user asked --install-deps
ensure_deps() {
  local missing=()
  for t in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then
      missing+=("$t")
    fi
  done
  # also suggest optional tools
  local opt_missing=()
  for t in "${OPTIONAL_TOOLS[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then
      opt_missing+=("$t")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    log "Missing required tools: ${missing[*]}"
    if [ "$DO_INSTALL_DEPS" = true ]; then
      install_missing "${missing[@]}"
    else
      err "Run with --install-deps to attempt automatic installation of missing tools."
    fi
  else
    log "All required tools present."
  fi

  if [ "${#opt_missing[@]}" -gt 0 ]; then
    log "Optional tools missing (recommended): ${opt_missing[*]}"
    if [ "$DO_INSTALL_DEPS" = true ]; then
      install_missing "${opt_missing[@]}"
    else
      log "You can install optional tools with --install-deps for extra features."
    fi
  fi
}

# safe URL encode for curl
url_encode() { python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(),safe=''))"; }

# retry wrapper for curl (simple)
curl_retry() {
  local url=$1; shift
  local out_file=${1:-""}; shift || true
  local retries=${1:-3}; shift || true
  local delay=${1:-2}; shift || true
  local code=0
  local i=0
  while [ $i -lt $retries ]; do
    if [ -n "$out_file" ]; then
      if curl -sS --fail -L "$url" -o "$out_file"; then
        code=0; break
      else code=$?; fi
    else
      if curl -sS --fail -L "$url"; then code=0; break; else code=$?; fi
    fi
    log "curl_retry: attempt $((i+1)) failed for $url (exit $code). Retrying in ${delay}s..."
    sleep "$delay"
    i=$((i+1))
  done
  return $code
}

# small helper to lower-case and trim email
norm_email() { printf "%s" "${1,,}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
md5_lower() { printf "%s" "$1" | tr 'A-Z' 'a-z' | md5sum | awk '{print $1}'; }

# trap cleanup
cleanup() {
  log "Exiting. You can find outputs in: $OUTDIR (if created)"
}
trap cleanup EXIT

### -------------------------
### Argument parsing
### -------------------------
if [ $# -eq 0 ]; then usage; fi

# initialize targets as empty
TARGET_EMAIL=""
TARGET_PHONE=""
TARGET_DOMAIN=""
TARGET_USERNAME=""
DO_ALL=false

while [ $# -gt 0 ]; do
  case "$1" in
    --email) shift; TARGET_EMAIL="$1"; shift;;
    --phone) shift; TARGET_PHONE="$1"; shift;;
    --domain) shift; TARGET_DOMAIN="$1"; shift;;
    --username) shift; TARGET_USERNAME="$1"; shift;;
    --all) shift; TARGET_DOMAIN="$1"; DO_ALL=true; shift;;
    --install-deps) DO_INSTALL_DEPS=true; shift;;
    --enable-active) ENABLE_ACTIVE=true; shift;;
    --concurrency) shift; CONCURRENCY="$1"; shift;;
    --rate) shift; RATE_LIMIT="$1"; shift;;
    --outdir) shift; OUTDIR="$1"; shift;;
    --no-csv) DO_CSV=false; shift;;
    --no-html) DO_HTML=false; shift;;
    --help) usage;;
    *) err "Unknown argument: $1"; usage;;
  esac
done

# Prepare output directory
if [ -z "$OUTDIR" ]; then
  OUTDIR="./osint_${TS}"
fi
mkdir -p "$OUTDIR"
logfile="$OUTDIR/run_${TS}.log"
touch "$logfile"
log "Starting $PROGNAME"
log "Output directory: $OUTDIR"
log "Concurrency: $CONCURRENCY, Rate per worker: ${RATE_LIMIT}s"

# Ensure dependencies if requested
ensure_deps

### -------------------------
### Modular lookup functions
### -------------------------
# We design each lookup to write its outputs into $OUTDIR and return quickly (non-blocking allowed)

gravatar_check() {
  local email="$1"
  local hash; hash=$(md5_lower "$email")
  local url="https://www.gravatar.com/avatar/${hash}?d=404"
  log "[gravatar] Checking $email"
  local dest="$OUTDIR/gravatar/${hash}.jpg"
  mkdir -p "$OUTDIR/gravatar"
  if curl -sI -L "$url" | grep -q "200 OK"; then
    curl -sL "$url" -o "$dest" && echo "$dest" >> "$OUTDIR/gravatar_info.txt"
    log "[gravatar] Found image for $email -> $dest"
  else
    log "[gravatar] No gravatar for $email"
    echo "none" > "$OUTDIR/gravatar_info.txt"
  fi
}

whois_lookup() {
  local target="$1"
  log "[whois] $target"
  local safe; safe=$(echo "$target" | sed 's/[^a-zA-Z0-9._-]/_/g')
  if command -v whois >/dev/null 2>&1; then
    whois "$target" > "$OUTDIR/whois_${safe}.txt" || true
  else
    curl_retry "https://rdap.org/domain/$target" "$OUTDIR/whois_${safe}.json" 3 2 || true
  fi
}

dns_lookup() {
  local domain="$1"
  log "[dns] $domain"
  mkdir -p "$OUTDIR/dns"
  if command -v dig >/dev/null 2>&1; then
    {
      echo "A records:"; dig +short A "$domain"
      echo -e "\nAAAA records:"; dig +short AAAA "$domain"
      echo -e "\nMX records:"; dig +short MX "$domain"
      echo -e "\nTXT records:"; dig +short TXT "$domain"
      echo -e "\nNS records:"; dig +short NS "$domain"
    } > "$OUTDIR/dns/dns_${domain}.txt" 2>/dev/null || true
  else
    # fallback to nslookup
    {
      echo "A records:"; nslookup -type=A "$domain" 2>/dev/null
      echo -e "\nMX records:"; nslookup -type=MX "$domain" 2>/dev/null
      echo -e "\nNS records:"; nslookup -type=NS "$domain" 2>/dev/null
    } > "$OUTDIR/dns/dns_${domain}.txt" 2>/dev/null || true
  fi
}

theharvester_domain() {
  local domain="$1"
  log "[theHarvester] $domain"
  if command -v theHarvester >/dev/null 2>&1; then
    mkdir -p "$OUTDIR/theharvester"
    theHarvester -d "$domain" -b all -f "$OUTDIR/theharvester/theharvester_${domain}" >/dev/null 2>&1 || true
  else
    log "[theHarvester] not present, skipping. (pip install theHarvester)"
  fi
}

sherlock_username() {
  local username="$1"
  log "[sherlock] $username"
  mkdir -p "$OUTDIR/sherlock"
  if [ -d "$OUTDIR/sherlock_repo" ]; then
    true
  else
    if command -v git >/dev/null 2>&1; then
      git clone --depth 1 https://github.com/sherlock-project/sherlock.git "$OUTDIR/sherlock_repo" >/dev/null 2>&1 || true
    fi
  fi
  if command -v python3 >/dev/null 2>&1 && [ -d "$OUTDIR/sherlock_repo" ]; then
    pushd "$OUTDIR/sherlock_repo" >/dev/null 2>&1
    python3 -m pip install -r requirements.txt >/dev/null 2>&1 || true
    python3 sherlock.py "$username" --json > "../sherlock/sherlock_${username}.json" || true
    popd >/dev/null 2>&1
  else
    log "[sherlock] python3 or repo missing, skipping"
  fi
}

breach_check_hibp() {
  local email="$1"
  if [ -z "${HIBP_API_KEY:-}" ]; then
    log "[hibp] HIBP_API_KEY not set; skipping"
    return
  fi
  log "[hibp] $email"
  local encoded; encoded=$(python3 - <<PY
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1],safe='') )
PY
"$email")
  curl_retry "https://haveibeenpwned.com/api/v3/breachedaccount/${encoded}" "$OUTDIR/hibp_${encoded}.json" 4 2 || true
}

hunter_email_verif() {
  local email="$1"
  if [ -z "${HUNTER_API_KEY:-}" ]; then
    log "[hunter] HUNTER_API_KEY not set; skipping"
    return
  fi
  log "[hunter] $email"
  local u; u=$(python3 - <<PY
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1],safe=''))
PY
"$email")
  curl_retry "https://api.hunter.io/v2/email-verifier?email=${u}&api_key=${HUNTER_API_KEY}" "$OUTDIR/hunter_${u}.json" 3 2 || true
}

shodan_lookup() {
  local ip="$1"
  if [ -z "${SHODAN_API_KEY:-}" ]; then
    log "[shodan] SHODAN_API_KEY not set; skipping"
    return
  fi
  log "[shodan] $ip"
  curl_retry "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" "$OUTDIR/shodan_${ip}.json" 3 2 || true
}

numverify_phone_lookup() {
  local phone="$1"
  if [ -z "${NUMVERIFY_API_KEY:-}" ]; then
    log "[numverify] NUMVERIFY_API_KEY not set; skipping"
    return
  fi
  log "[numverify] $phone"
  local enc; enc=$(python3 - <<PY
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1],safe=''))
PY
"$phone")
  curl_retry "http://apilayer.net/api/validate?access_key=${NUMVERIFY_API_KEY}&number=${enc}&format=1" "$OUTDIR/numverify_${enc}.json" 3 2 || true
}

emailrep_lookup() {
  local email="$1"
  if [ -z "${EMAILREP_API_KEY:-}" ]; then
    log "[emailrep] EMAILREP_API_KEY not set; skipping"
    return
  fi
  log "[emailrep] $email"
  local enc; enc=$(python3 - <<PY
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1],safe=''))
PY
"$email")
  curl_retry "https://emailrep.io/${enc}" "$OUTDIR/emailrep_${enc}.json" 3 2 || true
}

reverse_image_search_tips() {
  cat > "$OUTDIR/reverse_image_tips.txt" <<EOF
Reverse image search tips:
- Google Images: images.google.com -> upload or paste URL
- TinEye: tineye.com -> upload or paste URL
- Bing Visual Search: bing.com/images -> camera icon
Use exiftool (if installed) to inspect EXIF metadata: exiftool PATH_TO_IMAGE
EOF
}

google_dork_tips() {
  local target="$1"
  cat > "$OUTDIR/google_dorks_${target//[^a-zA-Z0-9]/_}.txt" <<EOF
Google dork examples for: $target
"$target"
site:linkedin.com "$target"
site:github.com "$target"
site:pastebin.com "$target"
site:facebook.com "$target"
site:$target "contact" OR "email" OR "phone"
EOF
}

active_nmap_scan() {
  local host="$1"
  if [ "$ENABLE_ACTIVE" != true ]; then
    log "[nmap] Active scans disabled; skipping $host"
    return
  fi
  if ! command -v nmap >/dev/null 2>&1; then
    err "[nmap] nmap not installed; skipping active scan"
    return
  fi
  log "[nmap] Scanning $host (ensure permission!)"
  nmap -sT -Pn -sV -oA "$OUTDIR/nmap_${host}" "$host" || true
}

### -------------------------
### Orchestration & concurrency
### -------------------------
# Worker pattern: build an array of "tasks" (command strings) and run them in limited concurrency
TASKS=()

enqueue() {
  TASKS+=("$*")
}

run_tasks() {
  # run tasks with concurrency
  local total=${#TASKS[@]}
  log "Running ${total} tasks with concurrency $CONCURRENCY"
  local i=0
  local pids=()
  for cmd in "${TASKS[@]}"; do
    # run command in a subshell to isolate
    (
      sleep 0.1 # micro stagger
      eval "$cmd"
    ) &
    pids+=($!)
    i=$((i+1))
    # throttle outstanding jobs
    while [ "$(jobs -rp | wc -l)" -ge "$CONCURRENCY" ]; do
      sleep "$RATE_LIMIT"
    done
  done
  # wait for all
  wait
  log "All tasks completed."
}

# summary collection helpers
CSV_SUMMARY="$OUTDIR/summary.csv"
echo "target,type,detail,file" > "$CSV_SUMMARY"

add_summary() {
  local target="$1"; shift
  local typ="$1"; shift
  local detail="$1"; shift
  local file="${1:-}"
  # escape commas in detail
  detail=${detail//,/\\,}
  echo "\"$target\",\"$typ\",\"$detail\",\"$file\"" >> "$CSV_SUMMARY"
}

# Add tasks based on provided targets
if [ -n "${TARGET_EMAIL}" ]; then
  email=$(norm_email "$TARGET_EMAIL")
  log "Queueing email checks for: $email"
  mkdir -p "$OUTDIR/email"
  enqueue "gravatar_check '$email' && add_summary '$email' 'gravatar' 'checked' '$OUTDIR/gravatar/${email//[^a-zA-Z0-9]/_}.jpg' || true"
  enqueue "breach_check_hibp '$email' && add_summary '$email' 'hibp' 'queried' '' || true"
  enqueue "hunter_email_verif '$email' && add_summary '$email' 'hunter' 'queried' '' || true"
  enqueue "emailrep_lookup '$email' && add_summary '$email' 'emailrep' 'queried' '' || true"

  # username/domain pivots
  username=$(printf "%s" "$email" | awk -F'@' '{print $1}')
  domain=$(printf "%s" "$email" | awk -F'@' '{print $2}')
  if [ -n "$username" ]; then
    enqueue "sherlock_username '$username' && add_summary '$username' 'sherlock' 'queried' '$OUTDIR/sherlock/sherlock_${username}.json' || true"
  fi
  if [ -n "$domain" ]; then
    enqueue "whois_lookup '$domain' && add_summary '$domain' 'whois' 'saved' '$OUTDIR/whois_${domain//[^a-zA-Z0-9]/_}.txt' || true"
    enqueue "dns_lookup '$domain' && add_summary '$domain' 'dns' 'saved' '$OUTDIR/dns/dns_${domain}.txt' || true"
    enqueue "theharvester_domain '$domain' && add_summary '$domain' 'theharvester' 'queried' '$OUTDIR/theharvester' || true"
    enqueue "google_dork_tips '$email' || true"
  fi
fi

if [ -n "${TARGET_PHONE}" ]; then
  phone="$TARGET_PHONE"
  log "Queueing phone checks for: $phone"
  mkdir -p "$OUTDIR/phone"
  enqueue "numverify_phone_lookup '$phone' && add_summary '$phone' 'numverify' 'queried' '' || true"
  enqueue "google_dork_tips '$phone' || true"
fi

if [ -n "${TARGET_DOMAIN}" ]; then
  domain="$TARGET_DOMAIN"
  log "Queueing domain checks for: $domain"
  mkdir -p "$OUTDIR/domain"
  enqueue "whois_lookup '$domain' && add_summary '$domain' 'whois' 'saved' '$OUTDIR/whois_${domain//[^a-zA-Z0-9]/_}.txt' || true"
  enqueue "dns_lookup '$domain' && add_summary '$domain' 'dns' 'saved' '$OUTDIR/dns/dns_${domain}.txt' || true"
  enqueue "theharvester_domain '$domain' && add_summary '$domain' 'theharvester' 'queried' '' || true"

  # shodan lookups per A record (best-effort)
  if command -v dig >/dev/null 2>&1; then
    ips=$(dig +short A "$domain" | tr '\n' ' ')
  else
    ips=$(nslookup -type=A "$domain" 2>/dev/null | awk '/^Address: /{print $2}' | tr '\n' ' ')
  fi
  for ip in $ips; do
    [ -n "$ip" ] && enqueue "shodan_lookup '$ip' && add_summary '$ip' 'shodan' 'queried' '' || true"
  done
fi

if [ -n "${TARGET_USERNAME}" ]; then
  username="$TARGET_USERNAME"
  log "Queueing username checks for: $username"
  mkdir -p "$OUTDIR/username"
  enqueue "sherlock_username '$username' && add_summary '$username' 'sherlock' 'queried' '$OUTDIR/sherlock/sherlock_${username}.json' || true"
  enqueue "google_dork_tips '$username' || true"
fi

# run tasks
run_tasks

# optional active scans (if enabled) - caution
if [ "$ENABLE_ACTIVE" = true ]; then
  if [ -n "${TARGET_DOMAIN}" ]; then
    for ip in $ips; do
      active_nmap_scan "$ip" || true
    done
  fi
fi

### -------------------------
### Reporting
### -------------------------
# Create a small HTML summary if requested
if [ "$DO_HTML" = true ]; then
  HTML="$OUTDIR/summary_${TS}.html"
  cat > "$HTML" <<HTML
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>OSINT Summary - $TS</title>
  <style>
    body{font-family:system-ui,Arial; padding:18px; max-width:1000px}
    table{border-collapse:collapse; width:100%}
    th,td{border:1px solid #ddd; padding:8px}
    th{background:#f2f2f2}
  </style>
</head>
<body>
  <h1>OSINT Summary - $TS</h1>
  <p>Source folder: $OUTDIR</p>
  <h2>CSV summary</h2>
  <pre>$(cat "$CSV_SUMMARY")</pre>
  <h2>Notes</h2>
  <p>Check detailed files in the output directory.</p>
</body>
</html>
HTML
  log "HTML summary saved to $HTML"
fi

log "CSV summary: $CSV_SUMMARY"
log "Run complete. All outputs saved to: $OUTDIR"
ls -la "$OUTDIR" | sed -n '1,200p'
