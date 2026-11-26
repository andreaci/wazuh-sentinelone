#!/usr/bin/env bash
# Installs the collector on a Linux Wazuh manager. Run as root after:
#   dotnet publish S1Wazuh.Collector -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o publish
set -euo pipefail
cd "$(dirname "$0")/.."

install -d -o wazuh -g wazuh /opt/s1wazuh /var/lib/s1wazuh /var/ossec/logs/sentinelone
install -d /etc/s1wazuh
install -m 755 publish/s1wazuh /opt/s1wazuh/s1wazuh
[ -f /etc/s1wazuh/appsettings.json ] || install -m 640 -g wazuh S1Wazuh.Collector/appsettings.json /etc/s1wazuh/appsettings.json
[ -f /etc/s1wazuh/s1wazuh.env ] || { printf 'SentinelOne__ApiToken=CHANGE_ME\n' > /etc/s1wazuh/s1wazuh.env; chmod 600 /etc/s1wazuh/s1wazuh.env; }
# The app reads appsettings.json from its working dir; point it at /etc via a symlink.
ln -sf /etc/s1wazuh/appsettings.json /opt/s1wazuh/appsettings.json

install -m 640 -o root -g wazuh deploy/wazuh/sentinelone_rules.xml /var/ossec/etc/rules/sentinelone_rules.xml
install -m 644 deploy/s1wazuh.service /etc/systemd/system/s1wazuh.service
systemctl daemon-reload

echo "Next: edit /etc/s1wazuh/s1wazuh.env and appsettings.json, add deploy/wazuh/ossec-localfile.xml to ossec.conf,"
echo "      then: systemctl restart wazuh-manager && systemctl enable --now s1wazuh"
