# wazuh-sone — SentinelOne → Wazuh

A small .NET 10 service that reads SentinelOne data through the Management API and writes it as JSON
lines that Wazuh ingests, decodes and alerts on.

```
SentinelOne API ──► s1wazuh ──► sentinelone-*.json ──► Wazuh logcollector ──► rules 100100+ ──► alerts / dashboard
 (read-only token)  (poll +      (NDJSON files)         (json log_format)
                     checkpoint)
```

| Source | API | Output file | Default |
|---|---|---|---|
| Threats | `GET /threats` | `sentinelone-threat.json` | on, every 60 s |
| Unified Alerts | GraphQL `/unifiedalerts/graphql` | `sentinelone-alert.json` | on, every 60 s |
| Activities (console audit log) | `GET /activities` | `sentinelone-activity.json` | on, every 60 s |
| Agents (inventory / health) | `GET /agents` | `sentinelone-agent.json` | on, hourly, only changed records |
| Deep Visibility events | `/dv/init-query` → `/dv/events` | `sentinelone-dv.json` | **off** (needs a query) |

Every line is `{"integration":"sentinelone","s1_source":"threat|alert|activity|agent|dv_event","s1_id":…,"s1_timestamp":…,"s1":{raw SentinelOne record}}`.

Contents: [1. Create the API token](#1-create-the-sentinelone-api-token) ·
[2. Configure](#2-configure-the-collector) · [3. Deploy](#3-deploy) ·
[4. Configure Wazuh](#4-configure-wazuh) · [5. Verify](#5-verify-end-to-end) ·
[6. Token rotation](#6-token-rotation) · [7. CI/CD and releases](#7-cicd-and-releases) ·
[8. Troubleshooting](#8-troubleshooting) · [9. Development](#9-development)

---

## 1. Create the SentinelOne API token

Use a **Service User**, never your personal token. A service user's token carries only the role and
scope you assign to it. A token generated from *My User → Generate API Token* inherits your own
privileges and breaks when your account changes.

### Steps (SentinelOne console)

1. Go to **Settings → Users → Service Users** → **Actions → Create New Service User**.
   (Menu names vary slightly between console versions.)
2. Name it e.g. `wazuh-collector`.
3. **Expiration:** SentinelOne recommends **no more than 1 month**. Use ≤ 30 days and plan
   [rotation](#6-token-rotation).
4. **Scope:** the narrowest that covers your data: the specific site(s) or the account.
5. **Role:** a read-only role. **Viewer** works for most sources; if you build a **Custom Role**, grant
   *View* on at least:

   | Data | Permission page |
   |---|---|
   | Threats | Threats → View |
   | Agents | Endpoints → View |
   | Activities | Activity / Audit → View |
   | Unified alerts | **Unified Alerts → View** (the sub-permissions for STAR/Endpoint/Identity/etc. alerts are optional) |
   | Deep Visibility (optional) | Deep Visibility → View/Run queries |

   Do **not** grant mitigation, remote shell, or any write/admin permission. The collector never needs them.
6. Create it and **copy the token immediately**; it is shown once.

### Test the token (read-only)

```bash
curl -s -H "Authorization: ApiToken $TOKEN" "https://YOURTENANT.sentinelone.net/web/api/v2.1/threats?limit=1" | head -c 300
```
`200` + JSON means token and scope work. `401` = bad/expired token, `403` = the role lacks that permission.

### Store it safely

- Provide it only as the environment variable **`SentinelOne__ApiToken`** (double underscore).
- Never commit it, put it in `appsettings.json`, or paste it into chat/tickets.

---

## 2. Configure the collector

Settings come from `appsettings.json` (next to the executable) and can be overridden by environment
variables, where `:` becomes `__` (e.g. `Sources__Threats__Enabled=false`).

| Setting | Meaning | Default |
|---|---|---|
| `SentinelOne:BaseUrl` | Console URL, e.g. `https://yourtenant.sentinelone.net` | required |
| `SentinelOne:ApiToken` | Use env `SentinelOne__ApiToken` instead | required |
| `SentinelOne:AccountIds` / `SiteIds` | Restrict scope (comma-separated IDs in env form `SentinelOne__SiteIds__0=…`) | all visible |
| `SentinelOne:PageSize` | Records per API page | 1000 |
| `Output:Directory` | Where NDJSON files are written (Wazuh reads here) | `/var/ossec/logs/sentinelone` |
| `Output:MaxFileSizeMb` / `RetainedFiles` | Size-based rotation (`.1`, `.2`, …) | 50 / 5 |
| `Output:MaxLineBytes` | Lines above this drop their largest fields and set `s1_truncated` (Wazuh truncates ~64 KB) | 60000 |
| `State:Directory` | Checkpoints; survive restarts without duplicates | `/var/lib/s1wazuh` |
| `Sources:<Name>:Enabled` | Turn a source on/off | see table above |
| `Sources:<Name>:IntervalSeconds` | Poll interval | 60 (agents 3600) |
| `Sources:<Name>:InitialLookbackHours` | How far back the **first** run reads | 24 |
| `Sources:Alerts:ViewType` | `ALL`, `ENDPOINT`, `CLOUD`, `IDENTITY`, `THIRD_PARTY`, `CUSTOM_ALERTS`, `DLP` | `ALL` |
| `Sources:Alerts:Selection` | GraphQL fields requested per alert, extend to collect more | sensible default |
| `Sources:DeepVisibility:Query` | Deep Visibility filter; **required** if enabled | — |

REST sources (`Threats`, `Activities`, `Agents`) also expose `Path`, `TimeFilterParam`, `SortBy`,
`IdPath`, `TimestampPath` so API differences can be handled in config without a rebuild.

**Behaviour:** failed requests (429/5xx/network) retry with exponential backoff and honour
`Retry-After`. A source that errors is logged and retried on the next interval, other sources keep
running. Checkpoints are written atomically; on restart the boundary records are de-duplicated.

---

## 3. Deploy

The collector writes files; **Wazuh must be able to read them** (see [section 4](#4-configure-wazuh)).
Pick one option.

### Option A: Linux binary on the Wazuh manager (recommended)

1. Download `s1wazuh-<version>-linux-x64.tar.gz` from the GitHub release (or build, see
   [section 9](#9-development)) and extract it:
   ```bash
   mkdir s1wazuh && tar -xzf s1wazuh-*-linux-x64.tar.gz -C s1wazuh && cd s1wazuh
   ```
2. Install (as root). This creates `/opt/s1wazuh`, `/var/lib/s1wazuh`, `/var/ossec/logs/sentinelone`,
   the systemd unit, and copies the Wazuh rules:
   ```bash
   sudo ./deploy/install.sh
   ```
3. Put the secret and tenant in the env file (kept `chmod 600`):
   ```bash
   sudo tee /etc/s1wazuh/s1wazuh.env >/dev/null <<'EOF'
   SentinelOne__BaseUrl=https://YOURTENANT.sentinelone.net
   SentinelOne__ApiToken=PASTE_TOKEN_HERE
   EOF
   sudo chmod 600 /etc/s1wazuh/s1wazuh.env
   ```
4. Adjust `/etc/s1wazuh/appsettings.json` if needed (sources, intervals, scope).
5. [Configure Wazuh](#4-configure-wazuh), then start the collector:
   ```bash
   sudo systemctl enable --now s1wazuh
   journalctl -u s1wazuh -f
   ```

### Option B: Docker

Image: `ghcr.io/andreaci/wazuh-sentinelone` (tags `latest`, `<version>`, `<commit sha>`).

```bash
docker run -d --name s1wazuh --restart unless-stopped \
  -e SentinelOne__BaseUrl=https://YOURTENANT.sentinelone.net \
  -e SentinelOne__ApiToken="$S1_TOKEN" \
  -v /var/ossec/logs/sentinelone:/var/ossec/logs/sentinelone \
  -v s1wazuh-state:/var/lib/s1wazuh \
  ghcr.io/andreaci/wazuh-sentinelone:latest
```
Docker Compose equivalent:
```yaml
services:
  s1wazuh:
    image: ghcr.io/andreaci/wazuh-sentinelone:latest
    restart: unless-stopped
    environment:
      SentinelOne__BaseUrl: https://YOURTENANT.sentinelone.net
      SentinelOne__ApiToken: ${S1_TOKEN}          # from a .env file or secret store; don't commit
      # Sources__DeepVisibility__Enabled: "true"
      # Sources__DeepVisibility__Query: 'EventType = "Process Creation"'
    volumes:
      - /var/ossec/logs/sentinelone:/var/ossec/logs/sentinelone   # shared with the Wazuh manager/agent
      - s1wazuh-state:/var/lib/s1wazuh
volumes:
  s1wazuh-state:
```
The bind-mounted host directory must be the one your Wazuh manager/agent reads. If Wazuh itself runs
in containers, mount the same host directory into the Wazuh container at the same path.
Container files are written as root; make them readable by the `wazuh` user
(`chmod -R a+rX /var/ossec/logs/sentinelone`, or run the container with `--user` matching it).

### Option C: Windows executable (as a Windows service + Wazuh agent)

For when the collector runs on a separate Windows host. A **Wazuh agent** on that host forwards
the files to your (Linux) manager.

1. Download `s1wazuh-<version>-win-x64.zip` from the release and extract it.
2. In an **elevated** PowerShell from the extracted folder:
   ```powershell
   .\deploy\install-windows.ps1 -BaseUrl https://YOURTENANT.sentinelone.net -ApiToken (Read-Host -AsSecureString "Token")
   ```
   It installs to `C:\Program Files\s1wazuh`, stores settings and the token as service-scoped
   environment, writes output to `C:\Program Files (x86)\ossec-agent\sentinelone`, and starts the
   `s1wazuh` service (auto-restart on failure).
3. In the **agent's** `ossec.conf` (`C:\Program Files (x86)\ossec-agent\ossec.conf`) add:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>C:\Program Files (x86)\ossec-agent\sentinelone\sentinelone-*.json</location>
   </localfile>
   ```
   and restart the agent (`Restart-Service wazuh`). Install the rules on the **manager** (section 4).

Running the same executable on a Linux **agent** host works the same way (use the Linux binary,
point `Output:Directory` where the agent reads, and add the `<localfile>` to the agent's `ossec.conf`).

---

## 4. Configure Wazuh

Two parts: read the files (on whichever host has the files: the manager or an agent), and install
the rules (always on the **manager**).

### 4.1 Read the files: `<localfile>`

Add to `/var/ossec/etc/ossec.conf` inside `<ossec_config>` on the host holding the files
(also in `deploy/wazuh/ossec-localfile.xml`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/sentinelone/sentinelone-*.json</location>
</localfile>
```
The built-in `json` decoder is used, so **no custom decoder is needed**. The `wazuh` user must be
able to read the files (the install script sets this up for Option A).

### 4.2 Install the rules (manager)

```bash
sudo install -m 640 -o root -g wazuh deploy/wazuh/sentinelone_rules.xml /var/ossec/etc/rules/sentinelone_rules.xml
sudo systemctl restart wazuh-manager
```
(`install.sh` already does the copy.) Rule IDs `100100`–`100150` are in Wazuh's custom range. Change them
if they clash with your own rules.

| Rule | Level | Triggers on |
|---|---|---|
| 100100 | 3 | any SentinelOne event (base) |
| 100110 | 7 | threat |
| 100111 | 9 | threat, confidence `suspicious` |
| 100112 | 12 | threat, confidence `malicious` |
| 100113 | 14 | malicious threat and `not_mitigated` |
| 100114 | 5 | threat marked as benign |
| 100120 | 7 | unified alert |
| 100121 | 10 | alert severity HIGH |
| 100122 | 13 | alert severity CRITICAL |
| 100130 | 3 | console activity |
| 100131 | 8 | failed console login |
| 100140 | 3 | agent record |
| 100141 | 10 | agent reports an active infection |
| 100142 | 5 | agent inactive/offline |
| 100143 | 4 | agent out of date |
| 100150 | 3 | Deep Visibility event |

Tune levels to your noise tolerance. Many tenants have lots of `suspicious` + `not_mitigated` threats,
so rule 100111 may be chatty at first.

### 4.3 Test the rules before going live

On the manager, paste a line from one of the output files into logtest:

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste e.g. the first line of sentinelone-threat.json, expect: rule 1001xx fired, level as in the table
```

### 4.4 View alerts

In the Wazuh dashboard → *Threat Hunting / Discover*, filter `rule.groups: sentinelone` (or
`sentinelone_threat`, `sentinelone_alert`, `sentinelone_activity`, `sentinelone_agent`, `sentinelone_dv`).
All raw SentinelOne fields appear under `data.s1.*`.

---

## 5. Verify end-to-end

```bash
systemctl status s1wazuh                                  # running
journalctl -u s1wazuh -n 50                               # "threat: emitted N new record(s)" etc.
ls -l /var/ossec/logs/sentinelone/                        # files growing, readable by wazuh
tail -n1 /var/ossec/logs/sentinelone/sentinelone-alert.json
grep -i sentinelone /var/ossec/logs/ossec.log | tail      # logcollector picked the files up
```
Then confirm alerts in the dashboard (4.4). To force a clean re-read, stop the service, delete the
relevant file in `/var/lib/s1wazuh/`, and start it again (the first run uses `InitialLookbackHours`).

---

## 6. Token rotation

Tokens expire (≤ 30 days recommended). **When the token expires the collector gets 401 and silently stops
collecting**, so rotate before expiry and set a calendar reminder ~5 days ahead.

1. In SentinelOne, generate a new token for the same service user.
2. Replace `SentinelOne__ApiToken` (env file, Docker secret, or the Windows service environment).
3. Restart (`systemctl restart s1wazuh` / `docker restart s1wazuh` / `Restart-Service s1wazuh`).
   Checkpoints persist, so nothing is lost or duplicated.
4. Confirm with `journalctl -u s1wazuh -n 20` that polling succeeds.

---

## 7. CI/CD and releases

`.github/workflows/ci.yml` runs on every push to `main`, tags `v*`, pull requests and manual dispatch:

| Job | What it does |
|---|---|
| `test` | `dotnet test` (xUnit) |
| `binaries` | Publishes self-contained **single-file** executables for **linux-x64** and **win-x64** (no .NET install needed), bundles `deploy/` (installers and Wazuh rules), README, and a SHA-256 file; uploads as workflow artifacts |
| `docker` | Builds the image from `deploy/Dockerfile`; on non-PR runs pushes to **GHCR** `ghcr.io/andreaci/wazuh-sentinelone` (tags: branch, semver, `latest` on main, commit SHA). PRs build but do not push |
| `release` | On a `v*` tag, attaches the Linux/Windows archives and checksums to a GitHub Release with generated notes |

**Cut a release:**
```bash
git tag v1.0.0 && git push origin v1.0.0
```
Version is taken from the tag (`v1.0.0` → `1.0.0`); other builds are `0.0.0-ci.<run number>`.

Repository setup: no secrets are needed. The workflow uses the built-in `GITHUB_TOKEN`. Under
*Settings → Actions → General → Workflow permissions* allow read/write so it can publish packages
and releases. After the first push, set the package visibility under the repo's *Packages* if you want others to pull it.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Startup error "ApiToken is required" / "BaseUrl must be an absolute URL" | Env vars missing; check the env file / `-e` flags (double underscore). |
| `401` in the log | Token wrong or expired, [rotate](#6-token-rotation). |
| `403` for one source | The service user's role lacks View on that area (section 1). |
| Alerts source empty, others fine | Role lacks *Unified Alerts → View*, or the scope has no alerts. |
| `400 … not a valid choice` | A configured `SortBy`/filter name isn't valid on your console version; override it in config. |
| Files written but nothing in Wazuh | `<localfile>` missing/wrong path, `wazuh` user can't read the files, or the manager wasn't restarted. Check `ossec.log`. |
| Events arrive but no rule fires | Rules not installed or manager not restarted; run `wazuh-logtest`. |
| Duplicate events after wiping state | Expected, the first run re-reads `InitialLookbackHours`. |
| `s1_truncated: true` | Record exceeded `MaxLineBytes`; the largest fields were dropped. Trim `Selection` or accept. |
| DV warning "hit MaxEventsPerQuery" | Narrow the query or lower `MaxWindowHours`; excess events were not collected. |

---

## 9. Development

```bash
dotnet test                                                              # unit tests
dotnet run --project S1Wazuh.Collector                               # run locally (set env vars, point Output/State at temp dirs)
dotnet publish S1Wazuh.Collector -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o publish/linux
dotnet publish S1Wazuh.Collector -c Release -r win-x64  --self-contained -p:PublishSingleFile=true -o publish/win
docker build -f deploy/Dockerfile -t s1wazuh .
```

Layout: `S1Wazuh.Collector` (service), `S1Wazuh.Tests`, `deploy/wazuh/` (rules + localfile snippet),
`deploy/` (installers, systemd unit, Dockerfile), `.github/workflows/ci.yml`.

**Validated** read-only against a live tenant: threats, unified alerts, activities, agents (field names in
the rules match real payloads). **Not yet validated:** Deep Visibility, `SiteIds`/`AccountIds` scoping for
unified alerts, and the rules inside a running Wazuh, so use `wazuh-logtest` first.
The legacy `/cloud-detection/alerts` endpoint returns nothing on current tenants; unified alerts replace it.
