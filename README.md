# CER-Discovery

Read-only PowerShell discovery toolkit + review deliverables for blueAPACHE's
Client Environment Review (CER) methodology.

## What's in this repo

| Path | What |
|---|---|
| `Invoke-CERDiscovery.ps1` | Orchestrator — entry point, `-Scope` selects which collectors run |
| `lib/` | Shared evidence/coverage/logging model (`CER.Common.ps1`, `CER.HostEvidence.ps1`) |
| `collectors/` | One script per data source (Entra, Intune, Exchange Online, DNS, Teams, Azure, AD, Windows Servers, vSphere, Veeam, FortiGate) |
| `agent/` | Standalone host-level local check, deployable via RMM (no dependency on `lib/`) |
| `build/` | `New-CEREvidencePack.ps1` — merges all collector output into the evidence pack |
| `mapping/controls-map.json` | Control-by-control automation coverage (auto/partial/manual, and where to find manual data) |
| `samples/hosts/` | Synthetic fixtures — try the host-evidence pipeline with zero live access |
| `deliverables/` | The Client Environment Review workbook (v1.1) and the two Word deliverables (Method & Report Template, Tool Coverage Matrix) this toolkit feeds |

## Read-only, by design

Every collector authenticates and reads only (`Invoke-MgGraphRequest -Method GET`,
`Get-*`/`Find-*`/`Search-AzGraph`, read-only REST calls). The only writes anywhere are
local output files under `output/` (git-ignored — treat evidence packs as client data,
never commit them) and a few session-scoped client settings (`Set-AzContext`,
`Set-PowerCLIConfiguration -Scope Session`). See the full toolkit doc below for the
complete breakdown.

## Quick start

See the full walkthrough below for prerequisites. Shortest path:

```powershell
.\Invoke-CERDiscovery.ps1 -Scope Entra,Intune,Exchange,DNS
```

Output lands in `output/<timestamp>/` — `evidence.csv`, `AutoEvidence.csv`
(paste-ready for the workbook's AutoEvidence tab), `coverage.md`, `summary.html`.

---

# CER-Discovery v1.0

Scripted evidence collection for the **Client Environment Review** (124 controls, 11 domains). It pulls what admin
access can reach — Entra/M365, Intune, Exchange Online/Purview, public DNS, Azure, on-prem AD, Windows servers over WinRM,
every endpoint via an RMM-deployed local check, and optionally vSphere, Veeam and FortiGate — and writes one evidence pack
per client run. It **does not score**: it tells you what it saw (with counts and names), flags what needs attention, and
says plainly which controls it could not cover and where that data lives.

Coverage at v1.0: **60 controls fully automated, 35 partly, 29 manual** (see `Client-Environment-Review-Tool-Coverage-Matrix-v1.0.docx`
or `mapping/controls-map.json`). Everything it finds is *input* to the workbook; you still decide the score.

```
CER-Discovery/
  Invoke-CERDiscovery.ps1          orchestrator (runs collectors, then builds the pack)
  collectors/  Get-CEREntra.ps1 · Get-CERIntune.ps1 · Get-CERExchangeOnline.ps1 · Get-CERDns.ps1 · Get-CERTeams.ps1 · Get-CERAzure.ps1
               Get-CERActiveDirectory.ps1 · Get-CERWindowsServers.ps1 · Get-CERvSphere.ps1 · Get-CERVeeam.ps1 · Get-CERFortiGate.ps1
  agent/       Invoke-CERLocalHostCheck.ps1 (RMM-deployable, no dependencies) · Import-CERLocalHostResults.ps1
  build/       New-CEREvidencePack.ps1 (evidence.csv, AutoEvidence.csv, coverage.md, summary.html)
  lib/         CER.Common.ps1 (evidence/coverage model, Graph paging, lifecycle tables) · CER.HostEvidence.ps1 (fleet roll-ups)
  mapping/     controls-map.json (control -> collectors, what the tool gives, where the rest lives)
  output/      <client>/<run-id>/ raw/ evidence/ coverage/ hosts/ logs/ + the pack files
```

## Output per run (`output\<client>\<yyyyMMdd-HHmm>\`)

| File | What |
|---|---|
| `evidence.csv` | One row per control: Status (Collected / Partial / Not run / Not collected / Manual), worst Flag (Attention / OK / Info), every evidence line with its collector, what the tool gives, where to find the rest |
| `AutoEvidence.csv` | Same, in the column order of the workbook's **AutoEvidence** tab — paste from A2 and the Checklist's *Tool status* / *Tool evidence* columns fill themselves |
| `coverage.md` | What ran, which sections failed and why (no access / not licensed / module missing), the not-run and manual lists with the place to look |
| `summary.html` | Readable report: Attention findings first, then every control by domain with its evidence and the manual pointer |
| `hosts.csv` | One line per host from the host check (OS, patch age, EDR, LAPS, local admins, SMBv1, TLS, AppLocker, macro policy, SQL, shares, serial) |
| `raw/*.json` | Everything the collectors pulled, per section — the audit trail behind each evidence line |

Raw output holds real names, UPNs, hostnames and IPs. **Keep it local**; only the sanitised report leaves the machine.

## Prerequisites

Cloud collectors (run from your bA laptop, Parallels session or a Mac — PowerShell 7 recommended, 5.1 works):

```powershell
Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement, Az.Accounts, Az.Resources, Az.ResourceGraph -Scope CurrentUser
Install-Module MicrosoftTeams -Scope CurrentUser        # optional (M365-07)
Install-Module VMware.PowerCLI -Scope CurrentUser       # optional (SRV-06/07) - can be large
```

On-prem collectors run on a **domain-joined jump host or DC** (Windows PowerShell 5.1 is fine) with RSAT: ActiveDirectory,
GroupPolicy, DnsServer, DhcpServer modules. WinRM must reach the servers (it usually does inside the estate; unreachable
hosts are reported as a finding, not an error). The Veeam collector needs the Veeam console/PowerShell module (run it on the VBR server).

Access, per bA practice (KB0012228 / KB0012557): your named `Admin.<F>.<Lastname>` account over **GDAP**. Roles that make
everything readable: **Global Reader + Security Reader** (Exchange/Purview/Intune/Secure Score/LAPS/BitLocker keys all read
under those). Azure: **Reader** on the subscriptions via Azure Lighthouse (connect to the bA tenant) or directly.

First Graph run in a tenant: a consent prompt for *Microsoft Graph Command Line Tools* appears — tick **Consent on behalf of
your organization** (needs a GDAP role that can consent, e.g. Global Administrator or Cloud Application Administrator), or
have the customer pre-consent once. If your GDAP role cannot consent, use `-UseDeviceCode` and consent from a browser session
that can, then re-run.

## Quick start

```powershell
# 1. Cloud pass (laptop). One run id per client review; write it down.
.\Invoke-CERDiscovery.ps1 -Client C-003 -Scope Cloud -RunId 20260905-0900 `
    -TenantId 11111111-2222-3333-4444-555555555555 `
    -UserPrincipalName admin.b.shrestha@blueapache.com -DelegatedOrganization contoso.onmicrosoft.com `
    -AzureTenantId <bA tenant id for Lighthouse>          # omit if the client has no Azure

# 2. On-prem pass (jump host / DC as domain admin) - same client and run id, any output root
.\Invoke-CERDiscovery.ps1 -Client C-003 -Scope OnPrem -RunId 20260905-0900 -OutputRoot D:\CER\output -IncludeDomainControllers
#    add -IncludeWindowsUpdateSearch for a live Windows Update scan on each server (+30-120 s per host)

# 3. Endpoints via RMM: deploy agent\Invoke-CERLocalHostCheck.ps1 (below), then import the JSON drops
.\Invoke-CERDiscovery.ps1 -Client C-003 -Scope Endpoints -RunId 20260905-0900 -LocalCheckPath \\FS01\CER$

# 4. Optional collectors (each on the box that has the module / API reachability)
.\collectors\Get-CERVeeam.ps1     -Client C-003 -RunId 20260905-0900 -VbrServer vbr01
.\collectors\Get-CERvSphere.ps1   -Client C-003 -RunId 20260905-0900 -VCenter vcsa01 -Credential (Get-Credential)
.\collectors\Get-CERFortiGate.ps1 -Client C-003 -RunId 20260905-0900 -FortiGate 10.0.0.1 -ApiToken (Read-Host -AsSecureString) -SkipCertificateCheck

# 5. Copy the on-prem run folder into the laptop's output\C-003\20260905-0900\ (merge) and rebuild the pack
.\build\New-CEREvidencePack.ps1 -Client C-003 -RunId 20260905-0900

# 6. Workbook: open output\C-003\20260905-0900\AutoEvidence.csv, copy rows, paste into the AutoEvidence tab from A2.
```

Try it without any access first: `.\Invoke-CERDiscovery.ps1 -Client DEMO -Scope Endpoints -LocalCheckPath .\samples\hosts` imports four
synthetic host results (a DC, a 2016 file/SQL server, a laptop, an unmanaged Windows 10 desktop) and builds a pack you can
paste into the workbook to see how the columns behave.

Every collector can also be run on its own with `-Client` / `-RunId` / `-OutputRoot` plus its own parameters; see the
comment block at the top of each file. Collectors never throw on a failed section — they record it in coverage and continue.

### Deploying the local host check through N-central / NinjaOne

Run as SYSTEM, 64-bit Windows PowerShell, on every workstation and server in the client's environment:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File Invoke-CERLocalHostCheck.ps1 -OutputPath "C:\ProgramData\CER" -OutputShare "\\FS01\CER$" -Quiet
```

Add `-IncludeWindowsUpdateSearch` if you want a live "pending updates" count (slower). Collect the `*.cer-host.json` files
(share, RMM file retrieval, or the script's stdout) into one folder and import them with `-Scope Endpoints -LocalCheckPath`.
The same function runs over WinRM for servers, so results are identical either way. Typical runtime 10-40 s per host.

## What each collector covers (short form)

| Collector | Main controls | Notes |
|---|---|---|
| Entra | IAM-01..14, M365-01/06/10/11/12, END-01/07/08, AZ-02, SEC-11 | Graph v1.0 (+ beta only in Intune). Sign-in log and Identity Protection sections need Entra P1/P2 and say so if absent |
| Intune | END-01..16, BDR-07, SEC-12 | Managed devices, compliance, update rings, settings catalog / endpoint security (ASR, LAPS, App Control), ADMX policies, Autopilot, MAM, detected apps |
| Exchange | M365-02/03/04/05/07/08/12, IAM-04, END-14, LIC-04 | `-DelegatedOrganization` for GDAP. Purview via Connect-IPPSSession. `-CheckInboxRules` scans inbox rules on up to 400 mailboxes |
| DNS | M365-02, NET-10, M365-05 | No credentials. SPF (incl. malformed multi-string records), DKIM selectors, DMARC, CAA, DNSSEC, MTA-STS, autodiscover |
| Teams | M365-07 | Optional module |
| Azure | AZ-01..07, BDR-01, SRV-02/03, NET-04, LIC-04 | Resource Graph for inventory/security/backup/cost; REST for budgets, Defender plans, diagnostics, 6-month cost |
| AD | IAM-01/05/09/10/11, SRV-02/05/09/10/11/12, END-02/08, M365-05, BDR-06, SEC-08, DOC-06, NET-01 | Run on DC/jump host. Also queries each DC over WinRM for SMBv1/LDAP signing/channel binding (skip with `-SkipDcRemote`) |
| Servers | SRV-*, END-* (servers), COV-02/04/05, SEC-02/03/12, IAM-10 (DCs) | WinRM fan-out of the host check; unreachable hosts listed |
| Endpoints | END-*, SEC-02/03/12, COV-04/05, BDR-07, END-16 | Import of RMM host-check JSON |
| vSphere | SRV-06/07, SRV-02, BDR-06 | Optional (PowerCLI) |
| Veeam | BDR-01/02/03/04/05/06/09, SRV-09 | Optional (VBR PowerShell) |
| FortiGate | NET-02/03/04/05/06/08/09, SEC-12 | Optional, **beta**: REST paths mirror the CLI tree; anything the firmware does not expose is reported as a gap |

Not automated in v1 (all listed with their source in the coverage matrix): BAMS/eFO/PowerBI reconciliation, Orion and
N-central console data, Huntress/Rapid7/Airlock/Mimecast/LionGard consoles, SNOW CIs and ticket trends, documentation
currency, DR plans and restore-test evidence, contracts/renewals, physical/UPS, insurance, roadmap. Linux hosts are not
covered by the host check.

## Reading the results

* **Attention** means the numbers deserve a look, not that the control fails. `OK` means the collector's own threshold was met.
  `Info` is context. Thresholds are deliberately strict (e.g. 95 % coverage) and are stated in the evidence text.
* A control marked **Not run** simply needs the named collector; **Not collected** means the collector ran but that section
  failed — `coverage.md` and `logs\<collector>.log` say why (403 = role/consent, "NotLicensed" = P1/P2/Defender missing,
  "NotInstalled" = module).
* Evidence lines carry `[Flag|Collector]` so you can trace them to `raw\<collector>.<section>.json`.

## Limits and known gaps

* Graph sign-in logs are capped (`-MaxSignIns`, default 5000 over 7 days); large tenants get a sample and a note.
* Mailbox inactivity checks up to `-MaxMailboxStats` (1500) mailboxes; inbox rules only with `-CheckInboxRules`.
* Intune settings-catalog/ASR/Autopilot endpoints are Graph **beta** (Microsoft documents them as such).
* Windows LAPS coverage from Entra requires DeviceLocalCredential.ReadBasic.All consent; BitLocker keys need BitLockerKey.ReadBasic.All.
* The host check reads HKLM policies plus loaded user hives; per-user Office policies of users not logged on are not visible.
* FortiGate: only `monitor/system/status`, `cmdb/firewall/policy`, `monitor/firewall/policy` and token auth are confirmed
  from documentation; other paths are derived from the CLI tree and may differ between firmware branches — treat as beta.
* Veeam immutability is read by property discovery (`*mmutab*`) because property names differ across versions.
* No throttling back-off beyond what the SDKs do; on 429s re-run the collector (it overwrites its own files only).

## Verified references (5 Sep 2026)

Graph `GET /directory/deviceLocalCredentials` (v1.0), `GET /admin/sharepoint/settings` (v1.0), Intune `configurationPolicies`
(beta) — Microsoft Learn; Essential Eight Maturity Model (last updated 27 Nov 2023) — cyber.gov.au; Windows Server 2016 EoS
12 Jan 2027, Server 2022 mainstream 13 Oct 2026, SQL 2016 EoS 14 Jul 2026, Windows 10 / Office 2016-19 / Exchange 2016-19 EoS
14 Oct 2025 — Microsoft Lifecycle; vSphere 7 EoGS 2 Oct 2025 — Broadcom KB; SSL-VPN tunnel mode removed in FortiOS 7.6.3 —
Fortinet docs; FortiGate REST `access_token` / `monitor/firewall/policy hit_count` — Fortinet docs and field guides.

## Version

1.0 — 5 Sep 2026 — initial release. blueAPACHE Portfolio Engineering (Bikash Shrestha). Internal tool; not for distribution to clients.
