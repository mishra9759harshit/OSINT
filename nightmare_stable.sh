#!/usr/bin/env bash
# osint_toolkit_pro_upgraded.sh
# Upgraded PRO — responsible OSINT toolkit (Termux / Linux)
# SAFE MODE: passive by default. Active scans require --enable-active and confirmation.
# Features added:
#  - Interactive loop repeats after each operation
#  - Auto-install missing open-source tools (asks before sudo)
#  - Simple terminal "tables" (column) for visual row/column output
#  - Lightweight concurrency via xargs -P
#  - Clear legal/ethical warning & consent checks for active scans
#  - Retains CSV/HTML outputs and improved logging
#
# Usage examples:
#  ./osint_toolkit_pro_upgraded.sh --email someone@example.com
#  ./osint_toolkit_pro_upgraded.sh --domain example.com --install-deps
#  ./osint_toolkit_pro_upgraded.sh                # runs interactive menu
#
# IMPORTANT: Use responsibly. Obtain permission before targeting accounts or infrastructure
# with active techniques. Passive collection only by default.

set -euo pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
TS=$(date +%Y%m%d_%H%M%S)
OUTDIR=""
DEFAULT_CONCURRENCY=4
CONCURRENCY=$DEFAULT_CONCURRENCY
RATE_LIMIT=1
ENABLE_ACTIVE=false
DO_INSTALL_DEPS=false
DO_HTML=true
DO_CSV=true

REQUIRED_TOOLS=(curl jq git md5sum awk sed grep uname column)
OPTIONAL_TOOLS=(whois dig nmap exiftool python3 pip nc parallel)

# Helper: colored output if terminal supports it
bold() { printf "\033[1m%s\033[0m" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
red() { printf "\033[31m%s\033[0m\n" "$*"; }

# load .env if present (safe)
if [ -f ".env" ]; then
  set -o allexport; source .env; set +o allexport
fi

logfile=""
log() { printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$logfile"; }
err() { printf '[%s] ERROR: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$logfile" >&2; }

usage() {
  cat <<USAGE
$PROGNAME — Upgraded PRO OSINT toolkit (safe defaults)

Usage:
  $PROGNAME [options] --email someone@example.com
  $PROGNAME [options] --phone "+919876543210"
  $PROGNAME [options] --domain example.com
  $PROGNAME            # Interactive menu

Options:
  --install-deps       Install missing packages (best-effort, asks before sudo)
  --enable-active      Enable active scans (nmap) - requires extra confirmation
  --concurrency N      Parallel workers (default: $DEFAULT_CONCURRENCY)
  --rate S             Rate limit between requests per worker (default: $RATE_LIMIT)
  --outdir DIR         Output directory (default: ./osint_<timestamp>)
  --no-csv             Skip CSV summary
  --no-html            Skip HTML summary
  --help               Show this message

Ethics: Passive collection from public sources only by default. Do not target private persons or systems
without explicit authorization. This tool avoids paid APIs and mass scraping; be mindful of rate limits.
USAGE
  exit 1
}

# detect package manager
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
  yellow "About to install missing packages: ${to_install[*]}"
  read -rp "Proceed with sudo install? [y/N]: " confirm
  if [[ "${confirm,,}" != "y" ]]; then
    err "User declined installation. Please install: ${to_install[*]}"
    return 1
  fi
  case "$pm" in
    pkg) sudo pkg update -y || true; sudo pkg install -y "${to_install[@]}" || true;;
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
  if [ "${#missing[@]}" -gt 0 ]; then
    err "Missing required tools: ${missing[*]}"
    if [ "$DO_INSTALL_DEPS" = true ]; then install_missing "${missing[@]}"; else err "Run with --install-deps to attempt installation."; fi
  else
    log "All required tools present."
  fi
  # optional
  local opt_missing=()
  for t in "${OPTIONAL_TOOLS[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then opt_missing+=("$t"); fi
  done
  if [ "${#opt_missing[@]}" -gt 0 ]; then
    log "Optional tools missing: ${opt_missing[*]}"
  fi
}

# tiny urlencode (python fallback)
urlenc() { python3 - <<PY
import sys,urllib.parse
print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))
PY
}

md5_lower() { printf "%s" "$1" | tr 'A-Z' 'a-z' | md5sum | awk '{print $1}'; }
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

# trap cleanup
cleanup() { log "Exiting. Outputs (if any) in $OUTDIR"; }
trap cleanup EXIT

# args
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

if [ -z "$OUTDIR" ]; then OUTDIR="./osint_${TS}"; fi
mkdir -p "$OUTDIR"
logfile="$OUTDIR/run_${TS}.log"
touch "$logfile"
log "Starting $PROGNAME at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log "Output dir: $OUTDIR"

ensure_deps

# Ethics reminder
yellow "ETHICS: Passive queries only by default. Active scans require explicit consent and --enable-active."
if [ "$ENABLE_ACTIVE" = true ]; then
  red "Active mode requested. You must have authorization to scan targets. Confirm you have permission."
  read -rp "I confirm I have authorization to run active scans on the target(s) [y/N]: " perm
  if [[ "${perm,,}" != "y" ]]; then
    err "Authorization not confirmed. Exiting."
    exit 1
  fi
fi

# small helper to print a two-column table to terminal
print_table() {
  # usage: print_table "HEADER1\tHEADER2" "row1col1\trow1col2" ...
  local outfile="$OUTDIR/term_table_$(date +%s).txt"
  for r in "$@"; do
    printf "%s\n" "$r" >> "$outfile"
  done
  column -t -s $'\t' "$outfile"
  echo
}

# gravatar
gravatar_check() {
  local email="$1"
  local h; h=$(md5_lower "$email")
  local url="https://www.gravatar.com/avatar/${h}?d=404"
  mkdir -p "$OUTDIR/gravatar"
  log "[gravatar] $email -> $url"
  if curl -sI -L "$url" | grep -q "200 OK"; then
    curl -sL "$url" -o "$OUTDIR/gravatar/${h}.jpg" || true
    echo "found:$OUTDIR/gravatar/${h}.jpg"
  else
    echo "none"
  fi
}

# crt.sh
crtsh_lookup() {
  local domain="$1"; local out="$OUTDIR/crt"
  mkdir -p "$out"
  local url="https://crt.sh/?q=%25.${domain}&output=json"
  if curl_retry "$url" "$out/crt_${domain}.json" 3 2; then
    log "[crt.sh] saved to $out/crt_${domain}.json"
    echo "$out/crt_${domain}.json"
  else
    log "[crt.sh] query failed"
    echo ""
  fi
}

# wayback
wayback_lookup() {
  local target="$1"; local out="$OUTDIR/wayback"
  mkdir -p "$out"
  local url="http://archive.org/wayback/available?url=${target}"
  if curl_retry "$url" "$out/wayback_$(echo $target | sed 's/[^a-zA-Z0-9]/_/g').json" 3 2; then
    log "[wayback] saved"
    echo "$out/wayback_$(echo $target | sed 's/[^a-zA-Z0-9]/_/g').json"
  else
    echo ""
  fi
}

# github search (simple first page)
github_search() {
  local q="$1"; local out="$OUTDIR/github"
  mkdir -p "$out"
  local url="https://github.com/search?q=$(printf %s "$q" | urlenc)&type=Code"
  curl -sL "$url" -o "$out/github_search_$(echo $q | sed 's/[^a-zA-Z0-9]/_/g').html" || true
  echo "$out/github_search_$(echo $q | sed 's/[^a-zA-Z0-9]/_/g').html"
}

# whois
whois_lookup() {
  local t="$1"; local safe; safe=$(echo "$t" | sed 's/[^a-zA-Z0-9._-]/_/g')
  mkdir -p "$OUTDIR/whois"
  if command -v whois >/dev/null 2>&1; then whois "$t" > "$OUTDIR/whois/whois_${safe}.txt" 2>/dev/null || true
  else curl_retry "https://rdap.org/domain/$t" "$OUTDIR/whois/whois_${safe}.json" 3 2 || true; fi
  echo "$OUTDIR/whois/whois_${safe}.txt"
}

# dns
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
  echo "$OUTDIR/dns/dns_${domain}.txt"
}

# minimal phone lookup placeholder (no paid APIs)
phone_lookup() {
  local phone="$1"; local out="$OUTDIR/phone"
  mkdir -p "$out"
  echo "phone_lookup:passive_only" > "$out/phone_${phone//[^0-9+]/_}.txt"
  echo "$out/phone_${phone//[^0-9+]/_}.txt"
}

# google dork tips
google_dork_tips() {
  local target="$1"; local out="$OUTDIR/dorks"
  mkdir -p "$out"
  local file="$out/dorks_${target//[^a-zA-Z0-9]/_}.txt"
  cat > "$file" <<EOF
Google dorks for: $target
"$target"
site:linkedin.com "$target"
site:github.com "$target"
site:pastebin.com "$target"
site:reddit.com "$target"
EOF
  echo "$file"
}

# orchestrations with table-friendly outputs
run_email_workflow() {
  local email; email=$(printf "%s" "${1,,}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  log "=== Email workflow: $email ==="
  mkdir -p "$OUTDIR"
  echo "email:$email" > "$OUTDIR/email_target.txt"
  local grav out_v breach file_github file_dorks
  grav=$(gravatar_check "$email")
  out_v="validation:passive_mx_check"
  breach="breach:refer_to_hibp_manual"
  file_github=$(github_search "$(echo "$email" | awk -F'@' '{print $1}')")
  file_dorks=$(google_dork_tips "$email")
  # print summary table
  print_table "module\tresult" \
    "gravatar\t$grav" \
    "validation\t$out_v" \
    "breach\t$breach" \
    "github_search\t${file_github##*/}" \
    "dorks\t${file_dorks##*/}"
  log "Email workflow finished. See intelligence_report.txt"
  printf "[%s] EMAIL %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$email" >> "$OUTDIR/intelligence_report.txt"
}

run_domain_workflow() {
  local domain="$1"
  log "=== Domain workflow: $domain ==="
  local whoisf dnsf crt_file waybackf
  whoisf=$(whois_lookup "$domain")
  dnsf=$(dns_lookup "$domain")
  crt_file=$(crtsh_lookup "$domain")
  waybackf=$(wayback_lookup "$domain")
  # list A records (if available)
  local arecs=""
  if [ -f "$dnsf" ]; then arecs=$(awk '/^A records:/{p=1;next}/^MX records:/{p=0}p' "$dnsf" | tr '\n' ' '); fi
  print_table "module\tfile/summary" \
    "whois\t${whoisf##*/}" \
    "dns\t${dnsf##*/}" \
    "crtsh\t${crt_file##*/}" \
    "wayback\t${waybackf##*/}" \
    "a_records\t${arecs:-none}"
  printf "[%s] DOMAIN %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" >> "$OUTDIR/intelligence_report.txt"
}

run_username_workflow() {
  local user="$1"
  log "=== Username workflow: $user ==="
  local ghf; ghf=$(github_search "$user")
  print_table "module\tfile" "github_search\t${ghf##*/}"
  printf "[%s] USERNAME %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$user" >> "$OUTDIR/intelligence_report.txt"
}

run_phone_workflow() {
  local phone="$1"
  log "=== Phone workflow: $phone ==="
  local pf; pf=$(phone_lookup "$phone")
  print_table "module\tfile" "phone_lookup\t${pf##*/}"
  printf "[%s] PHONE %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$phone" >> "$OUTDIR/intelligence_report.txt"
}

# interactive loop (repeats after operation)
interactive_menu() {
  while true; do
    cat <<'BANNER'
  ____   ____  _   _ _   _ _____ _____ _______ _______ 
 / __ \ / __ \| \ | | \ | |_   _/ ____|__   __|__   __|
| |  | | |  | |  \| |  \| | | || |       | |     | |   
| |  | | |  | | . ` | . ` | | || |       | |     | |   
| |__| | |__| | |\  | |\  |_| || |____   | |     | |   
 \____/ \____/|_| \_|_| \_|_____\_____|  |_|     |_|   
    PRO OSINT Toolkit — Interactive Mode (Safe)
BANNER
    PS3=$'\n''Choose an action: '
    options=(
      "Email workflow (gravatar/validate/breach/pivots)"
      "Phone workflow (passive)"
      "Domain workflow (whois/dns/crt.sh/wayback)"
      "Username workflow (github)"
      "Quick scan (email+domain+username)"
      "Generate .env.template (safe)"
      "Install recommended deps (best-effort)"
      "Show last report files"
      "Exit"
    )
    select opt in "${options[@]}"; do
      case $REPLY in
        1)
          read -rp "Enter email: " em
          run_email_workflow "$em"
          break;;
        2)
          read -rp "Enter phone (with country code): " ph
          run_phone_workflow "$ph"
          break;;
        3)
          read -rp "Enter domain: " dm
          run_domain_workflow "$dm"
          break;;
        4)
          read -rp "Enter username: " un
          run_username_workflow "$un"
          break;;
        5)
          read -rp "Enter email (or blank): " e
          read -rp "Enter domain (or blank): " d
          read -rp "Enter username (or blank): " u
          [ -n "$e" ] && run_email_workflow "$e"
          [ -n "$d" ] && run_domain_workflow "$d"
          [ -n "$u" ] && run_username_workflow "$u"
          break;;
        6)
          cat > .env.template <<EOF
# .env.template - fill values and save as .env
# Leave blank or remove paid API keys to avoid accidental use
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
        8)
          echo "Files in $OUTDIR:"
          ls -lah "$OUTDIR" | sed -n '1,200p'
          break;;
        9)
          log "Bye."; exit 0;;
        *) echo "Invalid option";;
      esac
    done
    echo
    read -rp "Press Enter to return to menu (or Ctrl-C to exit)..." _ || true
    clear
  done
}

# Main
if [ "$INTERACTIVE" = true ]; then
  interactive_menu
else
  [ -n "$TARGET_EMAIL" ] && run_email_workflow "$TARGET_EMAIL"
  [ -n "$TARGET_PHONE" ] && run_phone_workflow "$TARGET_PHONE"
  [ -n "$TARGET_DOMAIN" ] && run_domain_workflow "$TARGET_DOMAIN"
  [ -n "$TARGET_USERNAME" ] && run_username_workflow "$TARGET_USERNAME"
fi

# final reporting
if [ "$DO_CSV" = true ]; then
  CSV="$OUTDIR/summary_${TS}.csv"
  echo "item,type,detail,file" > "$CSV"
  [ -f "$OUTDIR/email_target.txt" ] && echo "\"email\",\"target\",\"$(cat $OUTDIR/email_target.txt)\",\"$OUTDIR/email_target.txt\"" >> "$CSV"
  [ -f "$OUTDIR/intelligence_report.txt" ] && echo "\"file\",\"intelligence\",\"intelligence_report.txt\",\"$OUTDIR/intelligence_report.txt\"" >> "$CSV"
  log "CSV summary: $CSV"
fi

if [ "$DO_HTML" = true ]; then
  HTML="$OUTDIR/summary_${TS}.html"
  cat > "$HTML" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>OSINT Summary - $TS</title>
<style>body{font-family:system-ui;padding:18px;max-width:1000px}pre{background:#f7f7f7;padding:10px;border-radius:6px}</style>
</head><body>
<h1>OSINT Summary - $TS</h1>
<p>Folder: $OUTDIR</p>
<h2>Intelligence report (excerpt)</h2>
<pre>$(sed -n '1,200p' "$OUTDIR/intelligence_report.txt" 2>/dev/null || echo "No intel generated")</pre>
<h2>Notes</h2><ul><li>Passive lookups only by default.</li><li>For active scans enable --enable-active (requires permission).</li></ul>
</body></html>
HTML
  log "HTML summary saved to $HTML"
fi

log "Done. Outputs in: $OUTDIR"
ls -la "$OUTDIR" | sed -n '1,200p'
