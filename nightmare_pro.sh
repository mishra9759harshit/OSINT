#!/usr/bin/env bash
# osint_toolkit_pro.sh
# PRO — Enhanced OSINT toolkit (Termux / Linux)
# Features:
#  - Auto-load .env, detect available API keys and use fallback chains
#  - Open-source lookups: crt.sh, wayback, GitHub basic search, paste checks
#  - Email / phone / domain / username workflows, interactive menu
#  - Intelligence summary generation and CSV/HTML outputs
#  - Safe defaults: no active intrusive scans unless --enable-active
#
# Usage examples:
#   ./osint_toolkit_pro.sh --email someone@example.com
#   ./osint_toolkit_pro.sh --domain example.com --install-deps
#   ./osint_toolkit_pro.sh                # runs interactive menu
#
# Place your API keys in .env (same folder) — this script auto-loads it.
# Example .env entries (already supported):
#   SHODAN_API_KEY="..."
#   NUMVERIFY_API_KEY="..."
#   LEAKCHECK_API_KEY="..."
#   EMAILREP_API_KEY="..."
#   MAILBOXLAYER_API_KEY="..."
#   VERIFALIA_API_KEY="..."
#   DEBOUNCE_API_KEY="..."
#
# IMPORTANT: Use responsibly. Passive recon only by default. Obtain permission for active scans.

set -euo pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
TS=$(date +%Y%m%d_%H%M%S)
OUTDIR=""
DEFAULT_CONCURRENCY=4
RATE_LIMIT=1
CONCURRENCY=$DEFAULT_CONCURRENCY
ENABLE_ACTIVE=false
DO_INSTALL_DEPS=false
DO_HTML=true
DO_CSV=true

REQUIRED_TOOLS=(curl jq git md5sum awk sed grep uname)
OPTIONAL_TOOLS=(whois dig nmap exiftool python3 pip nc)

# load .env if present
if [ -f ".env" ]; then
  # shellcheck disable=SC1091
  set -o allexport; source .env; set +o allexport
fi

logfile=""
log() { printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$logfile"; }
err() { printf '[%s] ERROR: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$logfile" >&2; }

usage() {
  cat <<USAGE
$PROGNAME — PRO OSINT toolkit

Usage:
  $PROGNAME [options] --email someone@example.com
  $PROGNAME [options] --phone "+919876543210"
  $PROGNAME [options] --domain example.com
  $PROGNAME [options] --username username
  $PROGNAME            # Interactive menu

Options:
  --install-deps       Install missing packages (best-effort)
  --enable-active      Enable active scans (nmap) - require permission
  --concurrency N      Parallel workers (default: $DEFAULT_CONCURRENCY)
  --rate S             Rate limit between requests per worker (default: $RATE_LIMIT)
  --outdir DIR         Output directory (default: ./osint_<timestamp>)
  --no-csv             Skip CSV summary
  --no-html            Skip HTML summary
  --help               Show this message

USAGE
  exit 1
}

# --- pkg manager helpers (same as before, minimal) ---
detect_pkg_mgr() {
  if command -v pkg >/dev/null 2>&1; then echo "pkg"
  elif command -v apt >/dev/null 2>&1; then echo "apt"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v apk >/dev/null 2>&1; then echo "apk"
  elif command -v yum >/dev/null 2>&1; then echo "yum"
  else echo "unknown"
  fi
}
install_missing() {
  local pm; pm=$(detect_pkg_mgr)
  local to_install=("$@")
  if [ "$pm" = "unknown" ]; then
    err "Unknown package manager. Install manually: ${to_install[*]}"; return 1
  fi
  case "$pm" in
    pkg) pkg update -y || true; pkg install -y "${to_install[@]}" || true;;
    apt) sudo apt update || true; sudo apt install -y "${to_install[@]}" || true;;
    pacman) sudo pacman -Syu --noconfirm "${to_install[@]}" || true;;
    apk) sudo apk update || true; sudo apk add "${to_install[@]}" || true;;
    yum) sudo yum install -y "${to_install[@]}" || true;;
  esac
}

ensure_deps() {
  local missing=()
  for t in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then missing+=("$t"); fi
  done
  local opt_missing=()
  for t in "${OPTIONAL_TOOLS[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then opt_missing+=("$t"); fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    log "Missing required tools: ${missing[*]}"
    if [ "$DO_INSTALL_DEPS" = true ]; then install_missing "${missing[@]}"; else err "Run with --install-deps to attempt installation."; fi
  else
    log "All required tools present."
  fi
  if [ "${#opt_missing[@]}" -gt 0 ]; then
    log "Optional tools missing: ${opt_missing[*]}"
    if [ "$DO_INSTALL_DEPS" = true ]; then install_missing "${opt_missing[@]}"; fi
  fi
}

# small utilities
md5_lower() { printf "%s" "$1" | tr 'A-Z' 'a-z' | md5sum | awk '{print $1}'; }
norm_email() { printf "%s" "${1,,}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
urlenc() { python3 - <<PY
import sys,urllib.parse
print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))
PY
}

curl_retry() {
  local url="$1"; local out="${2:-}"; local r="${3:-3}"; local d="${4:-2}"
  local i=0
  while [ $i -lt $r ]; do
    if [ -n "$out" ]; then
      if curl -sS --fail -L "$url" -o "$out"; then return 0; fi
    else
      if curl -sS --fail -L "$url"; then return 0; fi
    fi
    i=$((i+1)); sleep "$d"
  done
  return 1
}

# trap
cleanup() { log "Exiting. Outputs (if any) in $OUTDIR"; }
trap cleanup EXIT

# Parse args
if [ $# -eq 0 ]; then
  INTERACTIVE=true
else
  INTERACTIVE=false
fi

TARGET_EMAIL=""; TARGET_PHONE=""; TARGET_DOMAIN=""; TARGET_USERNAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --email) shift; TARGET_EMAIL="$1"; shift;;
    --phone) shift; TARGET_PHONE="$1"; shift;;
    --domain) shift; TARGET_DOMAIN="$1"; shift;;
    --username) shift; TARGET_USERNAME="$1"; shift;;
    --install-deps) DO_INSTALL_DEPS=true; shift;;
    --enable-active) ENABLE_ACTIVE=true; shift;;
    --concurrency) shift; CONCURRENCY="$1"; shift;;
    --rate) shift; RATE_LIMIT="$1"; shift;;
    --outdir) shift; OUTDIR="$1"; shift;;
    --no-csv) DO_CSV=false; shift;;
    --no-html) DO_HTML=false; shift;;
    --help) usage;;
    *) err "Unknown arg: $1"; usage;;
  esac
done

# Prepare output dir
if [ -z "$OUTDIR" ]; then OUTDIR="./osint_${TS}"; fi
mkdir -p "$OUTDIR"
logfile="$OUTDIR/run_${TS}.log"
touch "$logfile"
log "Starting $PROGNAME at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log "Output dir: $OUTDIR"

# Ensure deps if requested
ensure_deps

# -------------------------
# API availability detection & fallback policy
# -------------------------
# Priority lists (you can modify)
BREACH_SOURCES=("LEAKCHECK_API_KEY" "EMAILREP_API_KEY" "LEAKCHECK_WEB" "HIBP_WEB")
EMAIL_VALIDATE_SOURCES=("MAILBOXLAYER_API_KEY" "VERIFALIA_API_KEY" "DEBOUNCE_API_KEY" "MX_CHECK")
PHONE_SOURCES=("NUMVERIFY_API_KEY")

has_key() { [ -n "${!1:-}" ] && [ "${!1}" != "YOUR_${1}_HERE" ]; }

# show what is available
log "Detected API keys:"
for k in SHODAN_API_KEY NUMVERIFY_API_KEY LEAKCHECK_API_KEY EMAILREP_API_KEY MAILBOXLAYER_API_KEY VERIFALIA_API_KEY DEBOUNCE_API_KEY; do
  if has_key "$k"; then log "  - $k: AVAILABLE"; else log "  - $k: (missing)"; fi
done

# -------------------------
# Lookup modules (passive)
# -------------------------
gravatar_check() {
  local email="$1"
  local h; h=$(md5_lower "$email")
  local url="https://www.gravatar.com/avatar/${h}?d=404"
  log "[gravatar] $email -> $url"
  mkdir -p "$OUTDIR/gravatar"
  if curl -sI -L "$url" | grep -q "200 OK"; then
    curl -sL "$url" -o "$OUTDIR/gravatar/${h}.jpg" || true
    echo "found:$OUTDIR/gravatar/${h}.jpg"
  else
    echo "none"
  fi
}

# Breach check with fallback: LeakCheck -> EmailRep -> HIBP web fallback (manual)
breach_check() {
  local email="$1"; local outpref="$OUTDIR/breach"
  mkdir -p "$outpref"
  log "[breach] checking $email (fallbacks: LeakCheck -> EmailRep -> HIBP web link)"
  # 1) LeakCheck (if API key)
  if has_key "LEAKCHECK_API_KEY"; then
    local url="https://api.leakcheck.net/v2?api_key=${LEAKCHECK_API_KEY}&method=search&term=$(printf %s "$email" | urlenc)"
    curl_retry "$url" "$outpref/leakcheck_$(echo $email | sed 's/[^a-zA-Z0-9]/_/g').json" 3 2 || true
    log "[breach] LeakCheck queried"
    echo "leakcheck:$outpref/leakcheck_$(echo $email | sed 's/[^a-zA-Z0-9]/_/g').json"
    return
  fi
  # 2) EmailRep (reputation; sometimes includes breach hints)
  if has_key "EMAILREP_API_KEY"; then
    local e=$(printf %s "$email" | urlenc)
    curl_retry "https://emailrep.io/${e}" "$outpref/emailrep_${e}.json" 3 2 || true
    log "[breach] EmailRep queried"
    echo "emailrep:$outpref/emailrep_${e}.json"
    return
  fi
  # 3) HIBP web fallback (manual)
  log "[breach] No LeakCheck/EmailRep key. Use HIBP web lookup: https://haveibeenpwned.com/Account/Manage"
  echo "hibp_web:https://haveibeenpwned.com/Account/Manage"
}

# Email verification fallback: mailboxlayer -> verifalia -> debounce -> MX check
email_verify() {
  local email="$1"; local out="$OUTDIR/validate"
  mkdir -p "$out"
  log "[verify] verifying $email (mailboxlayer -> verifalia -> debounce -> mx)"
  if has_key "MAILBOXLAYER_API_KEY"; then
    local q=$(printf %s "$email" | urlenc)
    curl_retry "http://apilayer.net/api/check?access_key=${MAILBOXLAYER_API_KEY}&email=${q}&smtp=1&format=1" "$out/mailboxlayer_$(echo $email | sed 's/[^a-zA-Z0-9]/_/g').json" 3 2 || true
    log "[verify] mailboxlayer queried"
    echo "mailboxlayer:$out/mailboxlayer_$(echo $email | sed 's/[^a-zA-Z0-9]/_/g').json"
    return
  fi
  if has_key "VERIFALIA_API_KEY"; then
    log "[verify] Verifalia API key present (implement per Verifalia doc) - skipping auto call in this script"
    echo "verifalia:api_key_present"
    return
  fi
  if has_key "DEBOUNCE_API_KEY"; then
    local q=$(printf %s "$email" | urlenc)
    curl_retry "https://api.debounce.io/v1/?api=${DEBOUNCE_API_KEY}&email=${q}" "$out/debounce_$(echo $email | sed 's/[^a-zA-Z0-9]/_/g').json" 3 2 || true
    log "[verify] Debounce queried"
    echo "debounce:$out/debounce_$(echo $email | sed 's/[^a-zA-Z0-9]/_/g').json"
    return
  fi
  # fallback: MX presence and simple TCP connect on port 25 (non-intrusive)
  local domain; domain=$(printf "%s" "$email" | awk -F'@' '{print $2}')
  if [ -n "$domain" ]; then
    mkdir -p "$out/mx"
    if command -v dig >/dev/null 2>&1; then
      dig +short MX "$domain" > "$out/mx/mx_${domain}.txt" || true
    else
      nslookup -type=MX "$domain" > "$out/mx/mx_${domain}.txt" 2>/dev/null || true
    fi
    # try to test port 25 open on first MX (non-intrusive connect attempt)
    mx=$(awk '{print $2}' "$out/mx/mx_${domain}.txt" 2>/dev/null | head -n1 || true)
    if [ -n "$mx" ] && [ -n "$BASH_VERSION" ]; then
      # attempt /dev/tcp if available
      if ( exec 3<>/dev/tcp/"$mx"/25 ) 2>/dev/null; then
        echo "smtp_connect:open" > "$out/mx/smtp_${domain}.txt"
        exec 3>&-
        log "[verify] SMTP port 25 open on $mx (did not send commands)"
      else
        echo "smtp_connect:closed" > "$out/mx/smtp_${domain}.txt"
        log "[verify] SMTP port 25 closed or filtered on $mx"
      fi
    fi
    echo "mx_check:$out/mx/mx_${domain}.txt"
    return
  fi
  echo "verify:none"
}

# Phone lookup (numverify primary)
phone_lookup() {
  local phone="$1"; local out="$OUTDIR/phone"
  mkdir -p "$out"
  if has_key "NUMVERIFY_API_KEY"; then
    local e=$(printf %s "$phone" | urlenc)
    curl_retry "http://apilayer.net/api/validate?access_key=${NUMVERIFY_API_KEY}&number=${e}&format=1" "$out/numverify_$(echo $phone | sed 's/[^0-9+]/_/g').json" 3 2 || true
    log "[phone] numverify queried"
    echo "numverify:$out/numverify_$(echo $phone | sed 's/[^0-9+]/_/g').json"
    return
  fi
  echo "phone:none"
}

# Shodan lookup (if key)
shodan_lookup() {
  local ip="$1"; local out="$OUTDIR/shodan"
  mkdir -p "$out"
  if has_key "SHODAN_API_KEY"; then
    curl_retry "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" "$out/shodan_${ip}.json" 3 2 || true
    log "[shodan] queried $ip"
    echo "shodan:$out/shodan_${ip}.json"
  else
    echo "shodan:none"
  fi
}

# crt.sh certificates for domain
crtsh_lookup() {
  local domain="$1"; local out="$OUTDIR/crt"
  mkdir -p "$out"
  local url="https://crt.sh/?q=%25.${domain}&output=json"
  if curl_retry "$url" "$out/crt_${domain}.json" 3 2; then
    log "[crt.sh] saved to $out/crt_${domain}.json"
    echo "crtsh:$out/crt_${domain}.json"
  else
    log "[crt.sh] query failed (maybe rate-limited)"
    echo "crtsh:none"
  fi
}

# Wayback availability
wayback_lookup() {
  local target="$1"; local out="$OUTDIR/wayback"
  mkdir -p "$out"
  local url="http://archive.org/wayback/available?url=${target}"
  if curl_retry "$url" "$out/wayback_$(echo $target | sed 's/[^a-zA-Z0-9]/_/g').json" 3 2; then
    log "[wayback] saved"
    echo "wayback:$out/wayback_$(echo $target | sed 's/[^a-zA-Z0-9]/_/g').json"
  else
    echo "wayback:none"
  fi
}

# GitHub basic search (no auth) for email/username: scraping first page (best-effort)
github_search() {
  local q="$1"; local out="$OUTDIR/github"
  mkdir -p "$out"
  local url="https://github.com/search?q=$(printf %s "$q" | urlenc)&type=Code"
  # Keep it lightweight: just save HTML result
  curl -sL "$url" -o "$out/github_search_$(echo $q | sed 's/[^a-zA-Z0-9]/_/g').html" || true
  log "[github] saved search page for $q"
  echo "github:$out/github_search_$(echo $q | sed 's/[^a-zA-Z0-9]/_/g').html"
}

# Paste search (Pastebin / Searx / public paste scrapers). We'll try pastebin search via site: query saved as URL suggestion
paste_suggestions() {
  local q="$1"; local out="$OUTDIR/paste_suggestions"
  mkdir -p "$out"
  cat > "$out/paste_dorks_${q//[^a-zA-Z0-9]/_}.txt" <<EOF
Suggested manual paste searches for: $q
site:pastebin.com "$q"
site:ghostbin.com "$q"
site:bpaste.net "$q"
site:paste.ee "$q"
site:hastebin.com "$q"
Use these in a browser or search engine. Avoid aggressive scraping.
EOF
  log "[paste] suggestions saved"
  echo "paste_suggestions:$out/paste_dorks_${q//[^a-zA-Z0-9]/_}.txt"
}

# small helper to append to intelligence report
add_intel() {
  local tag="$1"; local detail="$2"
  printf "[%s] %s\n" "$tag" "$detail" >> "$OUTDIR/intelligence_report.txt"
}

# -------------------------
# Orchestration functions
# -------------------------
run_email_workflow() {
  local email; email=$(norm_email "$1")
  log "=== Email workflow: $email ==="
  echo "email:$email" > "$OUTDIR/email_target.txt"
  add_intel "TARGET" "email: $email"

  # 1. Gravatar
  gres=$(gravatar_check "$email")
  add_intel "GRAVATAR" "$gres"

  # 2. Validate
  vres=$(email_verify "$email")
  add_intel "VALIDATION" "$vres"

  # 3. Breach
  bres=$(breach_check "$email")
  add_intel "BREACH" "$bres"

  # 4. Username/domain pivots
  local user; user=$(printf "%s" "$email" | awk -F'@' '{print $1}')
  local domain; domain=$(printf "%s" "$email" | awk -F'@' '{print $2}')
  add_intel "PIVOT" "username:$user domain:$domain"

  if [ -n "$user" ]; then
    github_search "$user"
    sherlock_username "$user" 2>/dev/null || true
  fi
  if [ -n "$domain" ]; then
    whois_lookup "$domain"
    dns_lookup "$domain"
    crtsh_lookup "$domain"
    wayback_lookup "$domain"
  fi

  google_dork_tips "$email"
  paste_suggestions "$email"

  log "Email workflow finished. See intelligence_report.txt"
}

run_phone_workflow() {
  local phone="$1"
  log "=== Phone workflow: $phone ==="
  add_intel "TARGET" "phone: $phone"
  pres=$(phone_lookup "$phone")
  add_intel "PHONE" "$pres"
  google_dork_tips "$phone"
}

run_domain_workflow() {
  local domain="$1"
  log "=== Domain workflow: $domain ==="
  add_intel "TARGET" "domain: $domain"
  whois_lookup "$domain"
  dns_lookup "$domain"
  theharvester_domain "$domain"
  crtsh_lookup "$domain"
  wayback_lookup "$domain"
  # Shodan per IP
  local ips
  if command -v dig >/dev/null 2>&1; then ips=$(dig +short A "$domain" | tr '\n' ' '); else ips=$(nslookup -type=A "$domain" 2>/dev/null | awk '/^Address: /{print $2}'); fi
  for ip in $ips; do shodan_lookup "$ip"; done
  google_dork_tips "$domain"
}

run_username_workflow() {
  local user="$1"
  log "=== Username workflow: $user ==="
  add_intel "TARGET" "username: $user"
  github_search "$user"
  sherlock_username "$user" || true
  google_dork_tips "$user"
}

# Reuse some earlier helper functions (whois, dns, theharvester, sherlock, etc.)
whois_lookup() {
  local t="$1"; local safe; safe=$(echo "$t" | sed 's/[^a-zA-Z0-9._-]/_/g')
  mkdir -p "$OUTDIR/whois"
  if command -v whois >/dev/null 2>&1; then whois "$t" > "$OUTDIR/whois/whois_${safe}.txt" 2>/dev/null || true
  else curl_retry "https://rdap.org/domain/$t" "$OUTDIR/whois/whois_${safe}.json" 3 2 || true; fi
  log "[whois] saved"
}
dns_lookup() {
  local domain="$1"
  mkdir -p "$OUTDIR/dns"
  if command -v dig >/dev/null 2>&1; then
    {
      echo "A records:"; dig +short A "$domain"
      echo -e "\nMX records:"; dig +short MX "$domain"
      echo -e "\nTXT:"; dig +short TXT "$domain"
    } > "$OUTDIR/dns/dns_${domain}.txt" 2>/dev/null || true
  else nslookup -type=ANY "$domain" > "$OUTDIR/dns/dns_${domain}.txt" 2>/dev/null || true; fi
  log "[dns] saved"
}
theharvester_domain() {
  local domain="$1"
  if command -v theHarvester >/dev/null 2>&1; then mkdir -p "$OUTDIR/theharvester"; theHarvester -d "$domain" -b all -f "$OUTDIR/theharvester/theharvester_${domain}" >/dev/null 2>&1 || true; fi
}
sherlock_username() {
  local u="$1"; mkdir -p "$OUTDIR/sherlock"
  if [ -d "$OUTDIR/sherlock_repo" ]; then true; else git clone --depth 1 https://github.com/sherlock-project/sherlock.git "$OUTDIR/sherlock_repo" >/dev/null 2>&1 || true; fi
  if command -v python3 >/dev/null 2>&1 && [ -d "$OUTDIR/sherlock_repo" ]; then pushd "$OUTDIR/sherlock_repo" >/dev/null 2>&1; python3 -m pip install -r requirements.txt >/dev/null 2>&1 || true; python3 sherlock.py "$u" --json > "../sherlock/sherlock_${u}.json" || true; popd >/dev/null 2>&1; fi
}
theharvester_domain() { command -v theHarvester >/dev/null 2>&1 && theHarvester -d "$1" -b all -f "$OUTDIR/theharvester/${1}" >/dev/null 2>&1 || true; }

google_dork_tips() {
  local target="$1"; mkdir -p "$OUTDIR/dorks"
  cat > "$OUTDIR/dorks/dorks_${target//[^a-zA-Z0-9]/_}.txt" <<EOF
Google dorks for: $target
"$target"
site:linkedin.com "$target"
site:github.com "$target"
site:pastebin.com "$target"
site:reddit.com "$target"
site:github.com "password" "$target"
site:gitlab.com "$target"
site:stackoverflow.com "$target"
EOF
  log "[dorks] saved"
}

# -------------------------
# Interactive menu (hacker-themed)
# -------------------------
interactive_menu() {
  cat <<'BANNER'
  ____   ____  _   _ _   _ _____ _____ _______ _______ 
 / __ \ / __ \| \ | | \ | |_   _/ ____|__   __|__   __|
| |  | | |  | |  \| |  \| | | || |       | |     | |   
| |  | | |  | | . ` | . ` | | || |       | |     | |   
| |__| | |__| | |\  | |\  |_| || |____   | |     | |   
 \____/ \____/|_| \_|_| \_|_____\_____|  |_|     |_|   
    PRO OSINT Toolkit — Interactive Mode
BANNER
  PS3=$'\n''Choose an action: '
  options=(
    "Email workflow (gravatar/validate/breach/pivots)"
    "Phone workflow (numverify)"
    "Domain workflow (whois/dns/crt.sh/wayback/shodan)"
    "Username workflow (sherlock/github)"
    "Quick scan (email+domain+username)"
    "Generate .env template (safe)"
    "Install recommended deps (best-effort)"
    "Exit"
  )
  select opt in "${options[@]}"; do
    case $REPLY in
      1)
        read -rp "Enter email: " em; run_email_workflow "$em"; break;;
      2)
        read -rp "Enter phone (with country code): " ph; run_phone_workflow "$ph"; break;;
      3)
        read -rp "Enter domain: " dm; run_domain_workflow "$dm"; break;;
      4)
        read -rp "Enter username: " un; run_username_workflow "$un"; break;;
      5)
        read -rp "Enter email (or blank): " e; read -rp "Enter domain (or blank): " d; read -rp "Enter username (or blank): " u
        [ -n "$e" ] && run_email_workflow "$e"
        [ -n "$d" ] && run_domain_workflow "$d"
        [ -n "$u" ] && run_username_workflow "$u"
        break;;
      6)
        cat > .env.template <<EOF
# .env.template - fill values and save as .env
SHODAN_API_KEY=""
NUMVERIFY_API_KEY=""
LEAKCHECK_API_KEY=""
EMAILREP_API_KEY=""
MAILBOXLAYER_API_KEY=""
VERIFALIA_API_KEY=""
DEBOUNCE_API_KEY=""
EOF
        log "Template saved to .env.template"; break;;
      7)
        DO_INSTALL_DEPS=true; ensure_deps; break;;
      8) log "Bye."; exit 0;;
      *) echo "Invalid option";;
    esac
  done
}

# -------------------------
# Main execution
# -------------------------
if [ "$INTERACTIVE" = true ]; then
  interactive_menu
  # after interactive runs, produce short reports:
  echo; log "Generating final intelligence report..."
else
  # run workflows based on CLI args
  if [ -n "$TARGET_EMAIL" ]; then run_email_workflow "$TARGET_EMAIL"; fi
  if [ -n "$TARGET_PHONE" ]; then run_phone_workflow "$TARGET_PHONE"; fi
  if [ -n "$TARGET_DOMAIN" ]; then run_domain_workflow "$TARGET_DOMAIN"; fi
  if [ -n "$TARGET_USERNAME" ]; then run_username_workflow "$TARGET_USERNAME"; fi
fi

# -------------------------
# Final reporting
# -------------------------
# CSV summary (very light): collect high-level files and outputs
if [ "$DO_CSV" = true ]; then
  CSV="$OUTDIR/summary_${TS}.csv"
  echo "item,type,detail,file" > "$CSV"
  # dump some items if present
  [ -f "$OUTDIR/email_target.txt" ] && echo "\"email\",\"target\",\"$(cat $OUTDIR/email_target.txt)\",\"$OUTDIR/email_target.txt\"" >> "$CSV"
  [ -f "$OUTDIR/intelligence_report.txt" ] && echo "\"file\",\"intelligence\",\"intelligence_report.txt\",\"$OUTDIR/intelligence_report.txt\"" >> "$CSV"
  log "CSV summary: $CSV"
fi

# HTML summary
if [ "$DO_HTML" = true ]; then
  HTML="$OUTDIR/summary_${TS}.html"
  cat > "$HTML" <<HTML
<!doctype html>
<html>
<head><meta charset="utf-8"><title>OSINT Summary - $TS</title>
<style>body{font-family:system-ui;padding:18px;max-width:1000px}pre{background:#f7f7f7;padding:10px;border-radius:6px}</style>
</head><body>
<h1>OSINT Summary - $TS</h1>
<p>Folder: $OUTDIR</p>
<h2>Intelligence report (excerpt)</h2>
<pre>$(sed -n '1,200p' "$OUTDIR/intelligence_report.txt" 2>/dev/null || echo "No intel generated")</pre>
<h2>Notes</h2>
<ul><li>Passive lookups only by default.</li><li>For active scans enable --enable-active (requires permission).</li></ul>
</body></html>
HTML
  log "HTML summary saved to $HTML"
fi

log "All done. Outputs in: $OUTDIR"
ls -la "$OUTDIR" | sed -n '1,200p'
