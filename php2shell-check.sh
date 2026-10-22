#!/usr/bin/env bash
# php2shell-check.sh: post-PHP2Shell compromise triage for WordPress sites
#
# READ-ONLY. It lists and verifies; it never modifies or deletes anything.
#
# Usage:
#   ./php2shell-check.sh sites.txt              # check every site listed
#   ./php2shell-check.sh /var/www/example.com   # check one local site
#   ./php2shell-check.sh user@host:/var/www/html
#
# sites.txt holds one site per line, as a local path or an SSH target
# (user@host:path). Relative remote paths are relative to the SSH home dir.
# Put non-standard ports and keys in ~/.ssh/config. Lines starting with # are ignored.
#   /var/www/clientsite
#   deploy@203.0.113.10:/var/www/html
#   u123456@hostinger-box:domains/example.com/public_html
#
# Reports are written to ./php2shell-reports/<site>.md, plus SUMMARY.md.
#
# Optional environment variables:
#   SINCE=2026-10-17       start of the window to inspect (first known exploitation)
#   WP="wp"                wp-cli command on the target, e.g. WP="php $HOME/wp-cli.phar"
#   OUT=./php2shell-reports
#
# WP-CLI runs with --skip-plugins --skip-themes so a backdoored plugin or theme
# doesn't execute during the check.

set -uo pipefail

SINCE="${SINCE:-2026-10-17}"
WP="${WP:-wp}"
OUT="${OUT:-./php2shell-reports}"

# ---------------------------------------------------------------- helpers

FINDINGS=0
REVIEWS=0
flag()   { FINDINGS=$((FINDINGS + 1)); echo "- ⚠️ $*"; }
review() { REVIEWS=$((REVIEWS + 1));   echo "- 🔎 $*"; }
ok()     { echo "- ✅ $*"; }
note()   { echo "- ℹ️ $*"; }

# Print stdin as a fenced block, truncated to N lines (default 60).
block() {
  local n="${1:-60}" out count
  out="$(cat)"
  [ -z "$out" ] && return 0
  count="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  echo
  echo '```'
  printf '%s\n' "$out" | head -n "$n"
  [ "$count" -gt "$n" ] && echo "... ($((count - n)) more lines)"
  echo '```'
  echo
}

# Is version $1 >= version $2?
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# ---------------------------------------------------------------- checks

check_php() {
  echo "## PHP version"
  echo
  local v mm fixed
  v="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
  if [ -z "$v" ]; then
    note "PHP CLI not found on this machine. Check the version in the hosting panel."
    echo "<!-- php: unknown -->"
    echo
    return
  fi
  echo "<!-- php: $v -->"
  mm="$(echo "$v" | cut -d. -f1,2)"
  case "$mm" in
    8.2) fixed=8.2.35 ;;
    8.3) fixed=8.3.36 ;;
    8.4) fixed=8.4.27 ;;
    8.5) fixed=8.5.12 ;;
    *)   fixed="" ;;
  esac
  if [ -n "$fixed" ]; then
    if ver_ge "$v" "$fixed"; then
      ok "CLI PHP $v is at or above the fixed release ($fixed)."
    else
      flag "CLI PHP $v is below the fixed release ($fixed). Upgrade."
    fi
  elif ver_ge "$mm" "8.6"; then
    ok "CLI PHP $v is newer than the fixed branches."
  else
    case "$mm" in
      7.4|8.0|8.1)
        flag "CLI PHP $v is on an end-of-life branch. php.net shipped no release, but security-team backports exist via deb.sury.org, Remi and enterprise distros. Check the package changelog for the CVE IDs, and plan the move to 8.2+." ;;
      *)
        flag "CLI PHP $v is on an end-of-life branch with no fix at all. Move to 8.2+." ;;
    esac
  fi
  note "This is the command-line PHP. The web server (PHP-FPM / mod_php) can run a different version. Confirm with phpinfo() or the hosting panel."
  note "Distro packages (Ubuntu/Debian/RHEL) may backport the fix without changing the version number. Check the package changelog for CVE-2026-109618/109619."
  echo
}

check_core_files() {
  echo "## WordPress core integrity"
  echo
  local out rc
  out="$("${WPLOUD[@]}" core verify-checksums 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    ok "Core files match wordpress.org checksums."
  else
    flag "Core checksum problems (modified, missing, or unexpected files):"
    printf '%s\n' "$out" | grep -v '^Error: WordPress installation' | block 80
  fi
  echo
}

check_plugin_files() {
  echo "## Plugin integrity (wordpress.org plugins only)"
  echo
  local tmp_err out rows skipped
  tmp_err="$(mktemp)"
  out="$("${WPLOUD[@]}" plugin verify-checksums --all --format=csv 2>"$tmp_err")"
  # Keep only CSV data rows (plugin_name,file,message); drop the header and
  # any Success:/Warning: lines WP-CLI prints to stdout.
  out="$(printf '%s\n' "$out" | grep -E '^[^,]+,[^,]+,' | grep -v '^plugin_name,' || true)"
  rows="$(printf '%s\n' "$out" | grep -c . || true)"
  if [ "${rows:-0}" -gt 0 ]; then
    flag "$rows plugin file(s) don't match wordpress.org:"
    printf 'plugin_name,file,message\n%s\n' "$out" | block 80
  else
    ok "All verifiable plugins match wordpress.org checksums."
  fi
  # WP-CLI 2.12 says "...of plugin NAME, skipping."; older versions quote the name.
  skipped="$(grep -oE "of plugin [^ ,]+|plugin '[^']+'" "$tmp_err" | sed -E "s/^of plugin //; s/^plugin '//; s/'\$//" | sort -u | tr '\n' ' ')"
  if [ -n "$skipped" ]; then
    note "Not verifiable (premium/custom). Compare against a fresh download or your repo: $skipped"
  fi
  rm -f "$tmp_err"
  echo
}

check_uploads_php() {
  echo "## Executable files in uploads"
  echo
  local dir="$1/wp-content/uploads" files f bad=0 benign=0 list=""
  if [ ! -d "$dir" ]; then note "No uploads directory found."; echo; return; fi
  files="$(find "$dir" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.pht' \) 2>/dev/null)"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    # "Silence is golden" index.php stubs are harmless
    if [ "$(wc -c <"$f")" -lt 200 ] && grep -qi 'silence' "$f" 2>/dev/null; then
      benign=$((benign + 1))
    else
      bad=$((bad + 1))
      list+="$(ls -la "$f")"$'\n'
    fi
  done <<<"$files"
  if [ $bad -gt 0 ]; then
    flag "$bad PHP file(s) in uploads. Almost always malicious; inspect before deleting:"
    printf '%s' "$list" | block 60
  else
    ok "No executable PHP in uploads."
  fi
  [ $benign -gt 0 ] && note "$benign harmless 'Silence is golden' index stub(s) ignored."
  echo
}

check_recent_files() {
  echo "## PHP and config files modified since $SINCE"
  echo
  local out count
  # date -r FILE works on both GNU and BSD/macOS; find -printf is GNU-only.
  out="$(find "$1" -type f \( -name '*.php' -o -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' -o -name '*.ico' \) \
          -newermt "$SINCE" -not -path '*/cache/*' -not -path '*/node_modules/*' \
          -exec sh -c 'for f; do printf "%s  %s\n" "$(date -r "$f" "+%Y-%m-%d %H:%M")" "$f"; done' _ {} + 2>/dev/null | sort -r)"
  count="$(printf '%s\n' "$out" | grep -c . || true)"
  if [ "${count:-0}" -gt 0 ]; then
    review "$count file(s) changed since $SINCE. Expected if you updated plugins or core since then; anything else needs a look:"
    printf '%s\n' "$out" | block 100
  else
    ok "No PHP/config files modified since $SINCE (attackers can fake timestamps, so checksums above are the stronger test)."
  fi
  echo
}

check_prepend_and_mu() {
  echo "## Auto-prepend hooks and must-use plugins"
  echo
  local hits mu
  # Recurse through the site; check only the parent folder's own config files.
  hits="$( {
      grep -RIlsE 'auto_(prepend|append)_file' --include='.user.ini' --include='.htaccess' --include='php.ini' "$1"
      grep -IlsE 'auto_(prepend|append)_file' "$1/../.user.ini" "$1/../.htaccess" "$1/../php.ini"
    } 2>/dev/null | sort -u)"
  if [ -n "$hits" ]; then
    review "auto_prepend/append_file set. Legit for Wordfence (wordfence-waf.php); anything else is a red flag:"
    while IFS= read -r f; do
      grep -HnE 'auto_(prepend|append)_file' "$f"
    done <<<"$hits" | block 30
  else
    ok "No auto_prepend/append_file directives."
  fi
  mu="$1/wp-content/mu-plugins"
  if [ -d "$mu" ] && [ -n "$(ls -A "$mu" 2>/dev/null)" ]; then
    review "Must-use plugins present (they run on every request and don't show in the normal plugin list):"
    ls -la "$mu" | block 30
  else
    ok "No must-use plugins."
  fi
  echo
}

check_code_patterns() {
  echo "## Common backdoor code patterns in wp-content"
  echo
  local out
  out="$(grep -RIlsE --include='*.php' --include='*.ph*' \
    'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE))|assert\s*\(\s*\$_(POST|GET|REQUEST)|\$_(POST|REQUEST|COOKIE)\s*\[[^]]+\]\s*\(|preg_replace\s*\(\s*["'"'"'].*/e["'"'"']|create_function\s*\(.*\$_' \
    "$1/wp-content" 2>/dev/null | grep -v '/node_modules/' | head -n 200)"
  if [ -n "$out" ]; then
    review "Files with classic web-shell patterns (some obfuscated premium plugins trip this too):"
    printf '%s\n' "$out" | block 60
  else
    ok "No classic web-shell patterns found."
  fi
  echo
}

check_users() {
  echo "## Users"
  echo
  local admins recent
  admins="$("${WPCMD[@]}" user list --role=administrator --fields=ID,user_login,user_email,user_registered --format=table 2>&1)"
  note "Administrators. Confirm every one is expected:"
  printf '%s\n' "$admins" | block 40
  recent="$("${WPCMD[@]}" user list --fields=ID,user_login,user_email,user_registered,roles --format=csv 2>/dev/null \
            | awk -F, -v s="$SINCE" 'NR > 1 && $4 >= s')"
  if [ -n "$recent" ]; then
    review "Accounts registered since $SINCE:"
    printf 'ID,user_login,user_email,user_registered,roles\n%s\n' "$recent" | block 40
  else
    ok "No accounts registered since $SINCE."
  fi
  echo
}

check_database() {
  echo "## Database"
  echo
  local siteurl home prefix opts posts
  siteurl="$("${WPCMD[@]}" option get siteurl 2>/dev/null)"
  home="$("${WPCMD[@]}" option get home 2>/dev/null)"
  note "siteurl: \`$siteurl\` · home: \`$home\` (should both be the client's own domain)"
  # 'wp db prefix' prints nothing under --quiet; 'config get' does.
  prefix="$("${WPCMD[@]}" config get table_prefix 2>/dev/null)"
  if [ -z "$prefix" ]; then
    review "SKIPPED: couldn't read the table prefix, so options and posts were not scanned."
  else
    opts="$("${WPCMD[@]}" db query \
      "SELECT option_name, autoload, LENGTH(option_value) AS bytes FROM ${prefix}options WHERE option_value REGEXP 'eval[(]|base64_decode[(]|gzinflate[(]|String[.]fromCharCode|<script[^>]+src=' ORDER BY bytes DESC LIMIT 50" \
      --skip-column-names 2>/dev/null)"
    if [ -n "$opts" ]; then
      review "Options containing script tags or obfuscation functions (analytics/header-script plugins are legit hits):"
      printf 'option_name\tautoload\tbytes\n%s\n' "$opts" | block 50
    else
      ok "No suspicious content in options."
    fi
    posts="$("${WPCMD[@]}" db query \
      "SELECT ID, post_type, post_status, post_modified FROM ${prefix}posts WHERE post_content REGEXP 'eval[(]|base64_decode[(]|String[.]fromCharCode|<script[^>]+src=' AND post_type NOT IN ('revision') ORDER BY post_modified DESC LIMIT 50" \
      --skip-column-names 2>/dev/null)"
    if [ -n "$posts" ]; then
      review "Posts/pages with external scripts or obfuscation (embeds can be legit):"
      printf 'ID\tpost_type\tpost_status\tpost_modified\n%s\n' "$posts" | block 50
    else
      ok "No suspicious scripts in post content."
    fi
  fi
  echo
  echo "## Scheduled events"
  echo
  note "Look for hooks that don't match any plugin you recognize:"
  "${WPCMD[@]}" cron event list --fields=hook,next_run_relative,recurrence --format=table 2>&1 | block 60
  echo
}

check_server() {
  echo "## Server (current user's view)"
  echo
  local cron
  cron="$(crontab -l 2>/dev/null || true)"
  if [ -n "$cron" ]; then
    review "Crontab for $(whoami). Confirm each entry:"
    printf '%s\n' "$cron" | block 30
  else
    ok "No crontab for $(whoami)."
  fi
  if [ -f "$HOME/.ssh/authorized_keys" ]; then
    review "SSH authorized_keys for $(whoami). Confirm each key is yours:"
    awk '{print $1, $NF}' "$HOME/.ssh/authorized_keys" | block 20
  fi
  echo
}

# ---------------------------------------------------------------- one site

run_single() {
  local p="$1"
  FINDINGS=0
  REVIEWS=0
  WPCMD=()
  read -r -a WPCMD <<<"$WP"
  WPCMD+=(--path="$p" --skip-plugins --skip-themes)
  [ "$(id -u)" = "0" ] && WPCMD+=(--allow-root)
  # verify-checksums reports mismatches and unverifiable plugins as warnings,
  # which --quiet hides. Keep an un-quieted copy for those two commands.
  WPLOUD=("${WPCMD[@]}")
  WPCMD+=(--quiet)

  echo "# PHP2Shell check: $(hostname):$p"
  echo
  echo "Run $(date '+%Y-%m-%d %H:%M %Z'), window since $SINCE. Legend: ⚠️ likely problem · 🔎 review by hand · ✅ clean · ℹ️ info"
  echo

  if [ ! -f "$p/wp-config.php" ] && [ ! -f "$p/../wp-config.php" ]; then
    flag "No wp-config.php at $p. Is this the WordPress root?"
    echo
  fi

  check_php

  DB_OK=0
  if "${WPCMD[@]}" core version >/dev/null 2>&1; then
    note "WordPress $("${WPCMD[@]}" core version 2>/dev/null)"
    # Checksums only need the files; users/options/cron need a live database.
    if "${WPCMD[@]}" db query 'SELECT 1' >/dev/null 2>&1; then
      DB_OK=1
    else
      note "Database unreachable from here (wrong host, or a Docker/remote DB). User, database and cron checks will be skipped; run on the server or inside the container for those."
    fi
    echo
    check_core_files
    check_plugin_files
  else
    note "WP-CLI not available or can't load the site. Skipping checksum, user and database checks. Set WP= to point at wp-cli."
    echo
    WPCMD=()
    WPLOUD=()
  fi

  check_uploads_php "$p"
  check_recent_files "$p"
  check_prepend_and_mu "$p"
  check_code_patterns "$p"

  if [ ${#WPCMD[@]} -gt 0 ] && [ "$DB_OK" = 1 ]; then
    check_users
    check_database
  elif [ ${#WPCMD[@]} -gt 0 ]; then
    echo "## Users, database and scheduled events"
    echo
    review "SKIPPED: database unreachable. Admin accounts, injected options/posts and cron events were not checked."
    echo
  fi

  check_server

  echo "---"
  echo "**$FINDINGS likely problem(s), $REVIEWS item(s) to review.**"
  echo "<!-- findings: $FINDINGS reviews: $REVIEWS -->"
}

# ---------------------------------------------------------------- dispatcher

is_remote() { [[ "$1" =~ ^[^/]+:.+ ]]; }

slug() { echo "$1" | sed -E 's#[^A-Za-z0-9._-]+#_#g; s#^_+|_+$##g'; }

check_target() {
  local target="$1" report host path
  report="$OUT/$(slug "$target").md"
  if is_remote "$target"; then
    host="${target%%:*}"
    path="${target#*:}"
    echo "→ $target (ssh)" >&2
    if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$host" \
         "SINCE=$(printf '%q' "$SINCE") WP=$(printf '%q' "$WP") bash -s -- --single $(printf '%q' "$path")" \
         <"$SCRIPT" >"$report" 2>&1; then
      grep -q '<!-- findings:' "$report" || echo "SSH or remote run failed. See output above." >>"$report"
    fi
  else
    echo "→ $target" >&2
    run_single "$target" >"$report" 2>&1
  fi
  local php findings reviews
  php="$(grep --color=never -oE '<!-- php: [^ ]+' "$report" | head -n1 | awk '{print $3}')"
  findings="$(grep --color=never -oE 'findings: [0-9]+' "$report" | awk '{print $2}')"
  reviews="$(grep --color=never -oE 'reviews: [0-9]+' "$report" | awk '{print $2}')"
  printf '| %s | %s | %s | %s | [%s](%s) |\n' "$target" "${php:-?}" "${findings:-ERROR}" "${reviews:-?}" \
    "$(basename "$report")" "$(basename "$report")" >>"$OUT/SUMMARY.md"
}

main() {
  if [ "${1:-}" = "--single" ]; then
    run_single "${2:?path required}"
    exit 0
  fi
  if [ $# -lt 1 ]; then
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
  fi

  SCRIPT="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  mkdir -p "$OUT"
  {
    echo "# PHP2Shell check summary"
    echo
    echo "Run $(date '+%Y-%m-%d %H:%M %Z'), window since $SINCE."
    echo
    echo "| Site | CLI PHP | ⚠️ Problems | 🔎 Review | Report |"
    echo "|---|---|---|---|---|"
  } >"$OUT/SUMMARY.md"

  if [ -f "$1" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      line="$(echo "$line" | sed -E 's/#.*//; s/^[[:space:]]+|[[:space:]]+$//g')"
      [ -z "$line" ] && continue
      check_target "$line" </dev/null
    done <"$1"
  else
    for t in "$@"; do check_target "$t"; done
  fi

  echo >&2
  echo "Done. Summary: $OUT/SUMMARY.md" >&2
  cat "$OUT/SUMMARY.md" >&2
}

main "$@"
