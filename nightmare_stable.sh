#!/usr/bin/env bash
# osint_peak.sh — Ultimate Free OSINT Toolkit

set -euo pipefail
IFS=$'\n\t'
OUTDIR="./osint_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
logfile="$OUTDIR/run.log"
log() { printf '[%s] %s\n' "$(date +'%F %T')" "$*" | tee -a "$logfile"; }
err() { printf '[%s] ERROR: %s\n' "$(date +'%F %T')" "$*" | tee -a "$logfile" >&2; }

REQUIRED_TOOLS=(python3 pip3 git curl jq)
OSINT_TOOLS=(spiderfoot theHarvester sherlock maigret subfinder)

# Auto-install system dependencies
install_pkg() {
  if command -v apt >/dev/null; then sudo apt-get update; sudo apt-get install -y "$@"
  elif command -v yum >/dev/null; then sudo yum install -y "$@"
  elif command -v pacman >/dev/null; then sudo pacman --noconfirm -S "$@"
  elif command -v pkg >/dev/null; then pkg install -y "$@"
  fi
}

ensure_reqs() {
  for t in "${REQUIRED_TOOLS[@]}"; do
    command -v "$t" >/dev/null || install_pkg "$t"
  done
}

# Generic tool auto-installer
ensure_tool() {
  case "$1" in
    spiderfoot)
      command -v spiderfoot > /dev/null && return
      git clone https://github.com/smicallef/spiderfoot.git "$OUTDIR/spiderfoot_src"
      pip3 install -r "$OUTDIR/spiderfoot_src/requirements.txt"
      ln -sf "$OUTDIR/spiderfoot_src/sf.py" "$OUTDIR/spiderfoot"
      ;;
    theHarvester)
      command -v theHarvester > /dev/null && return
      pip3 install theHarvester
      ;;
    sherlock)
      command -v sherlock > /dev/null && return
      git clone https://github.com/sherlock-project/sherlock.git "$OUTDIR/sherlock_src"
      pip3 install -r "$OUTDIR/sherlock_src/requirements.txt"
      ln -sf "$OUTDIR/sherlock_src/sherlock/sherlock.py" "$OUTDIR/sherlock"
      ;;
    maigret)
      command -v maigret > /dev/null && return
      pip3 install maigret
      ;;
    subfinder)
      command -v subfinder > /dev/null && return
      curl -sfL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.tar.gz | tar xz -C "$OUTDIR"
      chmod +x "$OUTDIR/subfinder"
      ln -sf "$OUTDIR/subfinder" /usr/local/bin/subfinder || sudo ln -sf "$OUTDIR/subfinder" /usr/local/bin/subfinder
      ;;
    *)
      ;;
  esac
}

install_all_tools() {
  ensure_reqs
  for t in "${OSINT_TOOLS[@]}"; do ensure_tool "$t"; done
}

# OSINT workflows — Scans and saves output to OUTDIR
run_spiderfoot() {
  local target="$1"
  python3 "$OUTDIR/spiderfoot_src/sf.py" -s "$target" -u all -o csv > "$OUTDIR/spiderfoot_${target}.csv" 2>/dev/null || true
}

run_theharvester() {
  local target="$1"
  theHarvester -d "$target" -b all -f "$OUTDIR/theHarvester_${target}.xml" > "$OUTDIR/theHarvester_${target}.log" 2>/dev/null || true
}

run_sherlock() {
  local target="$1"
  python3 "$OUTDIR/sherlock_src/sherlock/sherlock.py" "$target" --print-found --timeout 10 > "$OUTDIR/sherlock_${target}.txt" 2>/dev/null || true
}

run_maigret() {
  local target="$1"
  maigret "$target" -j -o "$OUTDIR/maigret_${target}.json" > "$OUTDIR/maigret_${target}.log" 2>/dev/null || true
}

run_subfinder() {
  local target="$1"
  subfinder -d "$target" -o "$OUTDIR/subfinder_${target}.txt" > /dev/null 2>&1 || true
}

# Summarizes all tool outputs into a table
show_results_table() {
  printf "\n%-16s | %-20s | %-20s\n" "Tool" "Target" "Key Outcomes"
  printf "%s\n" "----------------+----------------------+----------------------"
  for f in $OUTDIR/*; do
    fn=$(basename "$f")
    case "$fn" in
      spiderfoot_*.csv) count=$(grep -c '^' "$f"); target=${fn#spiderfoot_}; target=${target%.csv}; printf "%-16s | %-20s | %-20s\n" "SpiderFoot" "$target" "$count rows" ;;
      theHarvester_*.log) target=${fn#theHarvester_}; target=${target%.log}; found=$(grep -Eoi 'total [0-9]+' "$f" | head -n1 | awk '{print $2}'); printf "%-16s | %-20s | %-20s\n" "theHarvester" "$target" "${found:-N/A} results" ;;
      sherlock_*.txt) target=${fn#sherlock_}; target=${target%.txt}; acc=$(grep -cE '^https?://' "$f"); printf "%-16s | %-20s | %-20s\n" "Sherlock" "$target" "$acc found" ;;
      maigret_*.log) target=${fn#maigret_}; target=${target%.log}; acc=$(grep -cE '"url":' "$OUTDIR/maigret_${target}.json" 2>/dev/null || echo 0); printf "%-16s | %-20s | %-20s\n" "Maigret" "$target" "$acc sites" ;;
      subfinder_*.txt) target=${fn#subfinder_}; target=${target%.txt}; sfacc=$(grep -cv '^$' "$f"); printf "%-16s | %-20s | %-20s\n" "Subfinder" "$target" "$sfacc subdomains" ;;
      *) ;;
    esac
  done
}

# --- Main CLI ---
usage() {
  echo "Usage: $0 --domain example.com [--username username]"
  exit 1
}
if [ $# -lt 2 ]; then usage; fi
TARGET_DOMAIN=""; TARGET_USERNAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) shift; TARGET_DOMAIN="$1"; shift;;
    --username) shift; TARGET_USERNAME="$1"; shift;;
    *) usage;;
  esac
done

install_all_tools

log "Starting scans..."
run_spiderfoot "$TARGET_DOMAIN"
run_theharvester "$TARGET_DOMAIN"
run_subfinder "$TARGET_DOMAIN"

if [ -n "$TARGET_USERNAME" ]; then
  run_sherlock "$TARGET_USERNAME"
  run_maigret "$TARGET_USERNAME"
fi

log "Scan complete. Results summary:"
show_results_table
