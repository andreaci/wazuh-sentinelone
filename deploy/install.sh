#!/usr/bin/env bash
# s1wazuh installer / updater for a Linux Wazuh manager.
#
#   curl -fsSLO https://raw.githubusercontent.com/andreaci/wazuh-sentinelone/refs/heads/main/deploy/install.sh
#   chmod +x install.sh
#   sudo ./install.sh
#
# Downloads the latest release, asks for the SentinelOne URL and API token, installs the binary + systemd
# service, installs the Wazuh rules, adds the <localfile> to ossec.conf, validates the Wazuh config and
# restarts the services. Safe to re-run: it upgrades the binary and keeps your existing configuration.
#
# Optional environment (for unattended installs):
#   S1WAZUH_VERSION=v0.1.0   install a specific release instead of the latest
#   S1_URL=https://TENANT.sentinelone.net   S1_TOKEN=...   skip the prompts
#   S1WAZUH_YES=1            assume "yes" to confirmations
set -euo pipefail

REPO="andreaci/wazuh-sentinelone"
VERSION="${S1WAZUH_VERSION:-latest}"
ASSET="s1wazuh-linux-x64.tar.gz"

APP_DIR=/opt/s1wazuh
CONF_DIR=/etc/s1wazuh
STATE_DIR=/var/lib/s1wazuh
OSSEC=/var/ossec
OUT_DIR=$OSSEC/logs/sentinelone
OSSEC_CONF=$OSSEC/etc/ossec.conf
RULES_DST=$OSSEC/etc/rules/sentinelone_rules.xml

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

confirm() { # confirm "question" -> 0 for yes (default yes)
  [ "${S1WAZUH_YES:-}" = 1 ] && return 0
  local a; read -r -p "$1 [Y/n] " a </dev/tty || return 0
  [[ -z "$a" || "$a" =~ ^[Yy] ]]
}

# ---------- preflight ----------
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo ./install.sh)."
[ "$(uname -s)" = Linux ] || die "Linux only."
case "$(uname -m)" in x86_64|amd64) ;; *) die "Only linux-x64 builds are published (this is $(uname -m).)";; esac
for c in curl tar sha256sum systemctl; do command -v "$c" >/dev/null || die "Missing required command: $c"; done
[ -d "$OSSEC" ] || die "$OSSEC not found. This installer targets the Wazuh manager host."
id wazuh >/dev/null 2>&1 || die "User 'wazuh' not found. Is the Wazuh manager installed on this host?"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ---------- download ----------
if [ "$VERSION" = latest ]; then
  URL="https://github.com/$REPO/releases/latest/download/$ASSET"
  API="https://api.github.com/repos/$REPO/releases/latest"
else
  URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
  API="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
fi

say "Downloading $VERSION release..."
if ! curl -fsSL -o "$TMP/$ASSET" "$URL" 2>/dev/null; then
  # Older releases used versioned asset names; look the asset up through the API.
  URL="$(curl -fsSL "$API" | grep -o '"browser_download_url": *"[^"]*linux-x64\.tar\.gz"' | head -1 | cut -d'"' -f4 || true)"
  [ -n "$URL" ] || die "Could not find a linux-x64 asset for release '$VERSION' in $REPO."
  curl -fsSL -o "$TMP/$ASSET" "$URL" || die "Download failed: $URL"
fi

if curl -fsSL -o "$TMP/$ASSET.sha256" "$URL.sha256" 2>/dev/null; then
  # The checksum file names the original asset; compare only the hash.
  want="$(cut -d' ' -f1 "$TMP/$ASSET.sha256")"
  have="$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)"
  [ "$want" = "$have" ] || die "Checksum mismatch for the downloaded archive."
  say "Checksum OK."
else
  warn "No checksum file found; skipping verification."
fi

mkdir "$TMP/pkg" && tar -xzf "$TMP/$ASSET" -C "$TMP/pkg"
[ -f "$TMP/pkg/s1wazuh" ] || die "Archive does not contain the s1wazuh binary."

# ---------- configuration (prompt) ----------
ENV_FILE="$CONF_DIR/s1wazuh.env"
WRITE_ENV=1
if [ -f "$ENV_FILE" ] && [ -z "${S1_TOKEN:-}" ]; then
  if confirm "Existing configuration found in $ENV_FILE. Keep it?"; then WRITE_ENV=0; fi
fi

if [ "$WRITE_ENV" = 1 ]; then
  S1_URL="${S1_URL:-}"
  while [ -z "$S1_URL" ]; do
    read -r -p "SentinelOne console URL (e.g. https://yourtenant.sentinelone.net): " S1_URL </dev/tty
  done
  S1_URL="${S1_URL%/}"; [[ "$S1_URL" =~ ^https:// ]] || die "URL must start with https://"
  S1_TOKEN="${S1_TOKEN:-}"
  while [ -z "$S1_TOKEN" ]; do
    read -r -s -p "SentinelOne API token (input hidden): " S1_TOKEN </dev/tty; echo
  done

  say "Testing the token (read-only call)..."
  # Token passed via stdin config so it never appears in the process list.
  code="$(printf 'header = "Authorization: ApiToken %s"\n' "$S1_TOKEN" |
          curl -s -K - -o /dev/null -w '%{http_code}' --max-time 30 "$S1_URL/web/api/v2.1/threats?limit=1" || true)"
  case "$code" in
    200) say "Token accepted (HTTP 200).";;
    401) warn "HTTP 401: the token is invalid or expired."; confirm "Continue anyway?" || exit 1;;
    403) warn "HTTP 403: valid token but the role lacks permissions (needs at least Threats -> View)."; confirm "Continue anyway?" || exit 1;;
    *)   warn "Unexpected result '$code' (wrong URL or no network?)."; confirm "Continue anyway?" || exit 1;;
  esac
fi

# ---------- install files ----------
say "Installing files..."
install -d -o wazuh -g wazuh "$APP_DIR" "$STATE_DIR" "$OUT_DIR"
install -d "$CONF_DIR"
install -m 755 "$TMP/pkg/s1wazuh" "$APP_DIR/s1wazuh"
[ -f "$CONF_DIR/appsettings.json" ] || install -m 640 -g wazuh "$TMP/pkg/appsettings.json" "$CONF_DIR/appsettings.json"
ln -sf "$CONF_DIR/appsettings.json" "$APP_DIR/appsettings.json"

if [ "$WRITE_ENV" = 1 ]; then
  ( umask 077
    printf 'SentinelOne__BaseUrl=%s\nSentinelOne__ApiToken=%s\n' "$S1_URL" "$S1_TOKEN" > "$ENV_FILE" )
  chmod 600 "$ENV_FILE"
fi
unset S1_TOKEN

install -m 644 "$TMP/pkg/deploy/s1wazuh.service" /etc/systemd/system/s1wazuh.service
systemctl daemon-reload

# ---------- Wazuh: rules + localfile ----------
say "Installing Wazuh rules..."
RULES_BACKUP=""
[ -f "$RULES_DST" ] && { RULES_BACKUP="$TMP/rules.bak"; cp "$RULES_DST" "$RULES_BACKUP"; }
install -m 640 -o root -g wazuh "$TMP/pkg/deploy/wazuh/sentinelone_rules.xml" "$RULES_DST"

OSSEC_BACKUP="$OSSEC_CONF.s1wazuh.bak"
if grep -q 'sentinelone-\*\.json' "$OSSEC_CONF"; then
  say "ossec.conf already reads the SentinelOne files."
else
  say "Adding <localfile> to $OSSEC_CONF (backup: $OSSEC_BACKUP)..."
  cp -p "$OSSEC_CONF" "$OSSEC_BACKUP"
  cat >> "$OSSEC_CONF" <<EOF

<!-- s1wazuh: SentinelOne events (managed by install.sh) -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>$OUT_DIR/sentinelone-*.json</location>
  </localfile>
</ossec_config>
EOF
fi

say "Validating the Wazuh configuration..."
if [ -x "$OSSEC/bin/wazuh-analysisd" ] && ! "$OSSEC/bin/wazuh-analysisd" -t 2>"$TMP/analysisd.err"; then
  cat "$TMP/analysisd.err" >&2
  warn "Wazuh rejected the configuration; reverting my changes. Nothing was restarted."
  [ -f "$OSSEC_BACKUP" ] && cp -p "$OSSEC_BACKUP" "$OSSEC_CONF"
  if [ -n "$RULES_BACKUP" ]; then cp "$RULES_BACKUP" "$RULES_DST"; else rm -f "$RULES_DST"; fi
  die "Aborted. Fix the issue above and re-run."
fi

# ---------- restart ----------
if confirm "Restart wazuh-manager now (required to load the rules and the log source)?"; then
  systemctl restart wazuh-manager
else
  warn "Skipped. Run 'systemctl restart wazuh-manager' before expecting alerts."
fi

say "Starting the collector..."
systemctl enable s1wazuh >/dev/null 2>&1
systemctl restart s1wazuh
sleep 5
systemctl --no-pager --lines=0 status s1wazuh | sed -n '1,4p' || true
journalctl -u s1wazuh --no-pager -n 8 2>/dev/null || true

cat <<EOF

Done.
  Service status  : systemctl status s1wazuh
  Collector logs  : journalctl -u s1wazuh -f
  Output files    : $OUT_DIR
  Collector config: $CONF_DIR/appsettings.json   (secrets: $ENV_FILE)
  Dashboard filter: rule.groups: sentinelone
Re-run this script any time to upgrade; your configuration is kept.
EOF
