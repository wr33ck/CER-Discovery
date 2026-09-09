# CER-Discovery

Read-only PowerShell discovery toolkit + review deliverables for blueAPACHE's
Client Environment Review (CER) methodology.

## What's in this repo

| Path | What |
|---|---|
| `Invoke-CERDiscovery.ps1` | Orchestrator — entry point, `-Scope` selects which collectors run |
| `lib/` | Shared evidence/coverage/logging model (`CER.Common.ps1`, `CER.HostEvidence.ps1`) |
| `collectors/` | One script per data source (Entra, Intune, Exchange Online, DNS, Teams, Azure, AD, DHCP, NPS, on-prem/hybrid Exchange, Windows Servers, vSphere, Veeam, FortiGate, NetScaler, Citrix, Parallels RAS) |
| `agent/` | Standalone host-level local check, deployable via RMM (no dependency on `lib/`) |
| `build/` | `New-CEREvidencePack.ps1` — merges all collector output into the evidence pack |
| `mapping/controls-map.json` | Control-by-control automation coverage (auto/partial/manual, and where to find manual data) |
| `samples/hosts/` | Synthetic fixtures — try the host-evidence pipeline with zero live access |
| `deliverables/` | The Client Environment Review workbook (v1.2) and the two Word deliverables (Method & Report Template v1.1, Tool Coverage Matrix v1.1) this toolkit feeds |

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
.\Invoke-CERDiscovery.ps1 -Client C-003 -Scope Entra,Intune,Exchange,DNS
```

Note `Exchange` means Exchange **Online**; the on-prem/hybrid server is `ExchangeOnPrem`.

Output lands in `output/<client>/<run-id>/` — `evidence.csv`, `AutoEvidence.csv`
(paste-ready for the workbook's AutoEvidence tab), `coverage.md`, `summary.html`.

---

# CER-Discovery v1.2

Scripted evidence collection for the **Client Environment Review** (125 controls, 11 domains). It pulls what admin
access can reach — Entra/M365, Intune, Exchange Online/Purview, public DNS, Azure, on-prem AD, DHCP, NPS/RADIUS,
on-prem/hybrid Exchange, Windows servers over WinRM, every endpoint via an RMM-deployed local check, and optionally
vSphere, Veeam, FortiGate, NetScaler, Citrix CVAD and Parallels RAS — and writes one evidence pack per client run.
It **does not score**: it tells you what it saw (with counts and names), flags what needs attention, and says plainly
which controls it could not cover and where that data lives.

Coverage at v1.2: **61 controls fully automated, 37 partly, 27 manual** (see `Client-Environment-Review-Tool-Coverage-Matrix-v1.1.docx`
or `mapping/controls-map.json`). Everything it finds is *input* to the workbook; you still decide the score.

v1.2 adds five collectors — `Dhcp`, `Nps`, `Citrix`, `NetScaler`, `ParallelsRas` — and **one new control, SRV-14**
(published application / VDI platform), so the workbook goes to v1.2 and both Word deliverables to v1.1. The other
four collectors report against existing control IDs. Two controls that were fully manual are now partly automated on
the back of the NPS collector: **NET-07** (802.1X for corporate Wi-Fi rather than a shared PSK) and **NET-11**
(network access control).

```
CER-Discovery/
  Invoke-CERDiscovery.ps1          orchestrator (runs collectors, then builds the pack)
  collectors/  Get-CEREntra.ps1 · Get-CERIntune.ps1 · Get-CERExchangeOnline.ps1 · Get-CERDns.ps1 · Get-CERTeams.ps1 · Get-CERAzure.ps1
               Get-CERActiveDirectory.ps1 · Get-CERDhcp.ps1 · Get-CERNps.ps1 · Get-CERExchangeHybrid.ps1
               Get-CERWindowsServers.ps1 · Get-CERvSphere.ps1 · Get-CERVeeam.ps1 · Get-CERFortiGate.ps1
               Get-CERNetScaler.ps1 · Get-CERCitrix.ps1 · Get-CERParallelsRas.ps1
  agent/       Invoke-CERLocalHostCheck.ps1 (RMM-deployable, no dependencies) · Import-CERLocalHostResults.ps1
  build/       New-CEREvidencePack.ps1 (evidence.csv, AutoEvidence.csv, coverage.md, summary.html)
  build/       Sync-CERControlText.ps1 (pulls Why it matters / Target state from the workbook into the control map)
  lib/         CER.Common.ps1 (evidence/coverage model, run-folder resolution, Graph paging, lifecycle tables) · CER.HostEvidence.ps1 (fleet roll-ups)
  mapping/     controls-map.json (control -> collectors, what the tool gives, where the rest lives)
  output/      <client>/<run-id>/ raw/ evidence/ coverage/ hosts/ logs/ + the pack files
```

## One review, one run folder

`New-CEREvidencePack.ps1` merges **one** run folder and nothing else, so every collector for a review has to write
into the same `output\<client>\<run-id>\`. Two things used to break that silently, and both are fixed in v1.1:

* the output root defaulted to the **caller's working directory**, so the same command from a different prompt wrote
  a different tree. It now resolves from the toolkit folder (override with `-OutputRoot` or `$env:CER_OUTPUT_ROOT`);
* an omitted `-RunId` minted a **fresh timestamp**, so a collector run on its own forked a new folder that the pack
  never saw. An omitted `-RunId` now reuses the newest run for that client if it started within the last 12 hours
  (`$env:CER_RUN_REUSE_HOURS` to change it), and says so on screen. `-NewRun` forces a fresh run id.

Pass `-RunId` explicitly for a multi-machine review — it is still the reliable way. If evidence does end up in the
wrong folder, the pack builder now says so, lists the orphaned runs in `coverage.md` and `summary.html`, and prints the
`Copy-Item` + rebuild commands to merge them.

## Reading summary.html

The report is a single self-contained page — no CDN, no external requests, safe to open from a share or email to
yourself. It has a sticky toolbar: free-text filter across control IDs, titles, evidence and hostnames; flag filters
(Attention / OK / Info / Unknown); and Expand detail to open every disclosure at once. Print CSS opens all detail and
drops the controls, so Ctrl+P gives a clean PDF.

Evidence lines are written as `Label: value; Label: value; ...`. The report splits them on the semicolons into labelled
bullets and puts anything past the fourth fact behind a "N more" disclosure, so a 700-character line reads as a short
list instead of a paragraph. The full text is always in `evidence.csv` and the raw JSON.

Every finding now reads as four things: **what was found** (the evidence), **why it matters** and **target state**
(quoted from the workbook Checklist), and **recommended** (what to do about this specific finding).

## Why it matters, target state, and recommended actions

Three different things, from three different places, deliberately kept apart:

| Shown as | Source | Scope |
|---|---|---|
| **Why it matters** | Workbook Checklist, column *Why it matters* | Per control — your wording, quoted |
| **Target state** | Workbook Checklist, column *Target state (baseline = score 2)* | Per control — your wording, quoted |
| **Recommended** | `Add-CEREvidence -Action` in the collector | Per **finding** — written against what actually tripped the threshold |

The first two are quoted from the workbook, never re-written here, so there is one source of truth and it is the
workbook. Refresh the copy in `controls-map.json` after editing the workbook:

```powershell
.\build\Sync-CERControlText.ps1              # -WhatIf to preview, -Workbook to point at another file
```

That script reads the .xlsx directly as zipped XML — no Excel, no ImportExcel module, no Python — so it runs on the bA
laptop and on a jump host, and it re-indents `controls-map.json` to match the committed style so the diff stays readable.

**Recommended** is authored per finding, in the collector, next to the threshold logic that raised the flag — because
that is the only place that knows *which* thing tripped. KRBTGT at 412 days earns "rotate it twice, 24 h apart", not a
general paragraph about AD hardening. 214 of the 215 evidence lines carry one (the exception is "no on-prem Exchange
found", where there is nothing to recommend). They are a **starting point to tailor, not a decision** — the tool still
does not score, and the client-specific recommendation is still yours to write into the workbook's Recommendation
column, which feeds Findings and Roadmap.

`evidence.csv` gains `WhyItMatters`, `TargetState` and `RecommendedActions` (de-duplicated, worst flag first).
`AutoEvidence.csv` keeps its existing seven columns in the existing order, so the workbook paste is unaffected.

It also carries an **Evidence by collector** table. Findings are filed under the 11 review domains, never by collector,
so that table is the only place a given collector's contribution is visible — if AD or ExchangeOnPrem ran and produced
nothing, that is where it shows.

### One JSON caveat worth knowing

Evidence written by a collector on **Windows PowerShell 5.1** (a DC or jump host) can come back from
`ConvertFrom-Json` as a *single* object whose `Control` / `Flag` / `Evidence` / `Collector` fields are parallel arrays,
rather than as N separate rows. Left alone that is poison: `$_.Control -eq 'IAM-10'` against an array returns the
matching elements instead of `$false`, so one collapsed entry matches **every** control and the report repeats the same
wall of text under all of them. The pack builder now normalises every entry on load (`Expand-CEREvidence`), unzipping
the parallel arrays back into rows and noting on the console when it had to. Nothing needs doing on the collector side,
and hand-merged evidence files are covered by the same guard.

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

## RADIUS shared secrets and the NPS collector

NPS has no useful `Get-*` surface — the `Nps` module exposes `Export-NpsConfiguration` and `Import-NpsConfiguration`
and nothing else — so reading the policy set means reading the exported XML. Microsoft documents that **that export
contains the RADIUS shared secret of every client and every remote RADIUS server group in clear text.**

Left alone that would put every client's RADIUS secret into `raw\*.json`, which is exactly the wrong place for it. So
`Get-CERNps.ps1`:

* runs the export **and the parse** on the NPS server, inside one `Invoke-Command`, so the file with the secrets in it
  never crosses the network and never lands on the reviewer's machine;
* writes the export to that server's own `%TEMP%`, never into the run folder;
* returns only parsed, redacted objects — a shared secret is reported as **present/absent and by length**, never by
  value — with a final regex sweep over the returned policy XML before anything leaves the machine;
* deletes the export in a `finally` block, overwriting it first, whether or not the parse succeeded.

Nothing under `output\` should ever contain a RADIUS secret. **If you extend this collector, keep that true.** The
secret length is reported because a short secret is the finding — RADIUS still leans on MD5, so a short shared secret
is crackable offline from captured traffic.

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

The published-application collectors each need their own vendor tooling, on the box that has it:

| Collector | Needs | Where to run it |
|---|---|---|
| `Citrix` | CVAD PowerShell SDK (`Citrix.Broker.*`) | A Delivery Controller, in **Windows PowerShell 5.1** — the SDK is still snapin-based on most releases and `Add-PSSnapin` does not exist in PowerShell 7. Or a jump host with the SDK, using `-AdminAddress` |
| `ParallelsRas` | `RASAdmin` module (ships with the RAS console) | The Parallels RAS connection broker, or any machine with the console using `-Server` |
| `NetScaler` | HTTPS to the NSIP and a **read-only** NetScaler account (command policy `read-only`, not nsroot) | Anywhere that can reach the appliance |
| `NPS` | The `Nps` module (present with the NPS role) | The NPS server itself, or any domain-joined host using `-NpsServer` (the export and parse run remotely, over one `Invoke-Command`) |

The **ExchangeOnPrem** collector needs the Exchange Management Shell. Either run it on the Exchange server itself from EMS
(simplest, and the only way to read the true build number from `ExSetup.exe` — `Get-ExchangeServer` shows the cumulative
update only and hides missing security updates), or run it anywhere domain-joined with `-ExchangeServer <fqdn>`, which opens
an implicit remoting session to `http://<fqdn>/PowerShell/` over Kerberos. The account needs a remote-PowerShell-enabled
mailbox and **View-Only Organization Management** (Organization Management also works). Extended Protection and TLS are read
over WinRM against each Exchange server; skip with `-SkipExchangeIisChecks`. Skip the whole collector where the client has
no on-prem Exchange — the AD collector already proves absence from the configuration partition.

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
#    OnPrem = AD + DHCP + NPS + ExchangeOnPrem + Servers
.\Invoke-CERDiscovery.ps1 -Client C-003 -Scope OnPrem -RunId 20260905-0900 -OutputRoot D:\CER\output -IncludeDomainControllers `
    -ExchangeServer exch01.contoso.local `      # omit if the client has no on-prem Exchange
    -NpsServer nps01,nps02                      # omit to check only the local host for the NPS role
#    add -IncludeWindowsUpdateSearch for a live Windows Update scan on each server (+30-120 s per host)

# 3. Endpoints via RMM: deploy agent\Invoke-CERLocalHostCheck.ps1 (below), then import the JSON drops
.\Invoke-CERDiscovery.ps1 -Client C-003 -Scope Endpoints -RunId 20260905-0900 -LocalCheckPath \\FS01\CER$

# 4. Optional collectors (each on the box that has the module / API reachability)
.\collectors\Get-CERVeeam.ps1     -Client C-003 -RunId 20260905-0900 -VbrServer vbr01
.\collectors\Get-CERvSphere.ps1   -Client C-003 -RunId 20260905-0900 -VCenter vcsa01 -Credential (Get-Credential)
.\collectors\Get-CERFortiGate.ps1 -Client C-003 -RunId 20260905-0900 -FortiGate 10.0.0.1 -ApiToken (Read-Host -AsSecureString) -SkipCertificateCheck

# 5. Published-application platform - whichever one the client runs
.\collectors\Get-CERParallelsRas.ps1 -Client C-003 -RunId 20260905-0900 -Server ras01.contoso.local
.\collectors\Get-CERCitrix.ps1       -Client C-003 -RunId 20260905-0900      # on a Delivery Controller, Windows PowerShell 5.1
.\collectors\Get-CERNetScaler.ps1    -Client C-003 -RunId 20260905-0900 -NetScaler 10.0.0.5 -Credential (Get-Credential) -SkipCertificateCheck

# 6. Copy the on-prem run folder into the laptop's output\C-003\20260905-0900\ (merge) and rebuild the pack
.\build\New-CEREvidencePack.ps1 -Client C-003 -RunId 20260905-0900

# 7. Workbook: open output\C-003\20260905-0900\AutoEvidence.csv, copy rows, paste into the AutoEvidence tab from A2.
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
| AD | IAM-01/05/09/10/11, SRV-02/05/09/10/11/12, END-02/08, M365-05, BDR-06, SEC-08, DOC-06, NET-01 | Run on DC/jump host. Also queries each DC over WinRM for SMBv1/LDAP signing/channel binding (skip with `-SkipDcRemote`). DHCP moved out to its own collector in v1.2 |
| DHCP | SRV-11, NET-01 | RSAT `DhcpServer`. Authorised servers, scope utilisation and failover, lease durations, option hygiene (incl. public resolvers handed to clients), the DNS registration credential, name protection, audit logging, database backup, conflict detection |
| NPS | NET-05/07/11, SEC-12, SRV-11 | **Beta.** RADIUS clients, connection request and network policies, the authentication methods actually allowed, accounting, and the Entra MFA extension. Reads config via `Export-NpsConfiguration` **on the NPS server** and redacts every shared secret before anything is persisted — see below |
| NetScaler | NET-02/04/05, SRV-10, SRV-14, LIC-02/03 | Optional, **beta**: NITRO REST with a read-only account. Firmware against the 7-year lifecycle, HA, Gateway vServers and their authentication, TLS posture, certificate expiry, management exposure |
| Citrix | SRV-14, SRV-02, LIC-02/03 | Optional, **beta**: CVAD on-prem via the broker SDK on a Delivery Controller, **Windows PowerShell 5.1**. Site/controller version on the LTSR/CR lifecycle table, catalogs and delivery groups, VDA registration and version spread, licensing model. Citrix DaaS (Cloud) is not covered |
| ParallelsRas | SRV-14, SRV-02, NET-05, LIC-02/03 | Optional, **beta**: `RASAdmin` module on the RAS broker. Farm/site layout, version against the Parallels lifecycle table, publishing agent and gateway redundancy, session host agent health, MFA and SAML, licence headroom, published items |
| ExchangeOnPrem | M365-02/03/04/05, IAM-01/04, SRV-02/03/04/09/10, BDR-06, LIC-02 | **Beta.** Exchange Management Shell, on the server or via `-ExchangeServer`. Builds and SU currency, hybrid + OAuth certificate, connectors and anonymous relay, virtual directory exposure and Basic auth, Extended Protection and TLS, databases and backup dates, on-prem mailbox residual |
| Servers | SRV-*, END-* (servers), COV-02/04/05, SEC-02/03/12, IAM-10 (DCs) | WinRM fan-out of the host check; unreachable hosts listed |
| Endpoints | END-*, SEC-02/03/12, COV-04/05, BDR-07, END-16 | Import of RMM host-check JSON |
| vSphere | SRV-06/07, SRV-02, BDR-06 | Optional (PowerCLI) |
| Veeam | BDR-01/02/03/04/05/06/09, SRV-09 | Optional (VBR PowerShell) |
| FortiGate | NET-02/03/04/05/06/08/09, SEC-12 | Optional, **beta**: REST paths mirror the CLI tree; anything the firmware does not expose is reported as a gap |

Not automated (all listed with their source in the coverage matrix): BAMS/eFO/PowerBI reconciliation, Orion and
N-central console data, Huntress/Rapid7/Airlock/Mimecast/LionGard consoles, SNOW CIs and ticket trends, documentation
currency, DR plans and restore-test evidence, contracts/renewals, physical/UPS, insurance, roadmap. Linux hosts are not
covered by the host check. Citrix DaaS (Citrix Cloud) is not covered — the control plane is cloud-hosted and needs a
Citrix Cloud API client against a different API, so a DaaS client leaves SRV-14 manual. RDS CAL counts still come from
RD Licensing Manager.

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
* ExchangeOnPrem is **beta** on the same basis: cmdlets and properties are verified against Microsoft Learn (8 Sep 2026)
  but it has not been run against a live hybrid estate. Property names vary across Exchange versions, so treat the first
  run's output as something to check rather than something to quote.
* The Exchange build table in `lib/CER.Common.ps1` (`$script:CERExchangeLatest`) is a point-in-time copy of the published
  build numbers, verified 8 Sep 2026. A stale table under-reports missing security updates, which is the entire point of
  the check — refresh it from aka.ms/exchangebuildnumbers when the SU currency finding matters.
* Extended Protection is an IIS setting, not an Exchange one, so it is read over WinRM with the WebAdministration module.
  Where a server is unreachable the control is reported Unknown, not OK — run aka.ms/ExchangeHealthChecker on it instead.
* Whether an Exchange virtual directory with an external URL is genuinely reachable from the internet depends on firewall
  policy, a WAF, or the Hybrid Agent. The collector reports the published URL and says so; confirm actual exposure.
* Veeam immutability is read by property discovery (`*mmutab*`) because property names differ across versions.
* No throttling back-off beyond what the SDKs do; on 429s re-run the collector (it overwrites its own files only).
* **NPS is beta.** The exported configuration schema differs between Windows Server versions, so the collector walks it
  by element and property *name* rather than by a fixed path. If a section comes back empty on a given server, compare
  it against `netsh nps show config` before concluding the setting is absent.
* NPS proves a network policy exists; it cannot prove any switch port actually enforces 802.1X, nor that clients
  validate the NPS server certificate for PEAP — both are the client and switch side of the same control (NET-11).
* **Citrix is beta** and CVAD on-prem only. The broker SDK is snapin-based on most releases, so it needs Windows
  PowerShell 5.1; property names for the site version have moved between releases and are read by trying several in
  turn. Citrix DaaS is out of scope.
* **NetScaler is beta** on the same basis as FortiGate: the `/nitro/v1/config/` base, the login object and
  `lbvserver`/`sslvserver`/`sslcertkey`/`vpnvserver` are confirmed from Citrix developer documentation; the rest is
  derived from the CLI tree and may differ between firmware branches.
* Parallels RAS cmdlet coverage varies across RAS 18-21, so every call beyond `New-RASSession`, `Get-RASVersion` and
  `Get-RASSite` is guarded by `Get-Command` and degrades to a recorded coverage gap.
* The three new lifecycle tables in `lib/CER.Common.ps1` (`$script:CERRasLifecycle`, `$script:CERCitrixLifecycle`,
  `$script:CERNetScalerLifecycle`) are point-in-time copies verified 8 Sep 2026, exactly like the Exchange one. A stale
  table under-reports an out-of-support farm, which is the whole point of the check — two dates in them land inside the
  next year (**NetScaler 13.1 end of maintenance 15 Sep 2026** and **CVAD 2203 LTSR end of life 23 Mar 2027**), so
  refresh them before leaning on the result.
* The DHCP collector reads Windows DHCP only. Where the firewall or a router serves DHCP, that half of SRV-11 stays
  manual and the collector says so rather than reporting a clean result.

## Verified references (5 Sep 2026)

Graph `GET /directory/deviceLocalCredentials` (v1.0), `GET /admin/sharepoint/settings` (v1.0), Intune `configurationPolicies`
(beta) — Microsoft Learn; Essential Eight Maturity Model (last updated 27 Nov 2023) — cyber.gov.au; Windows Server 2016 EoS
12 Jan 2027, Server 2022 mainstream 13 Oct 2026, SQL 2016 EoS 14 Jul 2026, Windows 10 / Office 2016-19 / Exchange 2016-19 EoS
14 Oct 2025 — Microsoft Lifecycle; vSphere 7 EoGS 2 Oct 2025 — Broadcom KB; SSL-VPN tunnel mode removed in FortiOS 7.6.3 —
Fortinet docs; FortiGate REST `access_token` / `monitor/firewall/policy hit_count` — Fortinet docs and field guides.

### Added for v1.1 (8 Sep 2026, all Microsoft Learn)

* Exchange Server build numbers and release dates — latest builds Exchange Server SE RTM Aug26SU `15.2.2562.46`,
  Exchange 2019 CU15 Aug26SU `15.2.1748.49` / CU14 Aug26SU `15.2.1544.44`, Exchange 2016 CU23 Aug26SU `15.1.2507.72`
  (all 11 Aug 2026). Exchange 2016 and 2019 are out of support; Dec 2025 and later SUs need the paid ESU programme.
  `Get-Command ExSetup.exe | %{$_.FileVersionInfo}` gives the true build; `Get-ExchangeServer -AdminDisplayVersion`
  shows the CU only and hides SUs.
* Configure Windows Extended Protection in Exchange Server — `tokenChecking` values None/Allow/Require; recommended per
  front-end virtual directory (API/ECP/MAPI/OWA `Required`, EWS/ActiveSync/OAB `Allow`, AutoDiscover `None`), sslFlags
  `Ssl,Ssl128`; on by default from Exchange 2019 CU14; requires SSL offloading off for Outlook Anywhere, consistent TLS
  across all Exchange servers, and `LmCompatibilityLevel` ≥ 3.
* Maintain the Exchange Server OAuth certificate — `(Get-AuthConfig).CurrentCertificateThumbprint | Get-ExchangeCertificate`;
  expiry breaks hybrid free/busy and OWA/ECP sign-in; rotate at least 48 h ahead.
* Allow anonymous relay on Exchange servers / Receive connectors in Exchange Server — the two ways relay is granted:
  `PermissionGroups AnonymousUsers` plus `ms-Exch-SMTP-Accept-Any-Recipient` to `NT AUTHORITY\ANONYMOUS LOGON`, or
  `AuthMechanism ExternalAuthoritative` with `PermissionGroups ExchangeServers`.
* `Get-HybridConfiguration` — on-premises only.

### Added for v1.2 (8 Sep 2026)

* **Parallels RAS lifecycle** — kb.parallels.com/en/123002 (last reviewed 27 Feb 2026): LTS versions get 30 months
  maintenance + 6 months support (36 total), non-LTS 18 + 6. RAS 18 EOM 16 Jun 2023 / EOS 16 Dec 2023; RAS 19 EOM
  28 Feb 2025 / EOS 28 Jul 2025; RAS 20 EOM 30 Mar 2027 / EOS 30 Oct 2027; RAS 21 EOM 11 May 2028 / EOS 11 Nov 2028.
  The article states that any version not in its table has already reached both EOM and EOS.
* **Parallels RAS PowerShell** — `RASAdmin` module, `New-RASSession` before anything else, then `Get-RASVersion`,
  `Get-RASSite`, `Get-RASRDS`, `Get-RASGateway`, `Get-RASGatewayStatus`, `Get-RASLicenseDetails`, `Get-RASMFA`,
  `Get-RASMFACriteria`, `Get-RASMFADefaultSettings` (docs.parallels.com RAS PowerShell API guide, v20/v21).
* **CVAD lifecycle** — Citrix product matrix and endoflife.date/citrix-vad (updated 6 Sep 2026). Current Releases:
  active support ends 6 months after release, security support at 18 months. LTSR: 5 years active+security, then up to
  5 more years of **paid** extended support. 2607 LTSR (18 Aug 2026 → 17 Aug 2029), 2507 LTSR (→ 18 Aug 2028, ext 2033),
  2402 LTSR (→ 15 Apr 2029, ext 2034), **2203 LTSR (→ 23 Mar 2027**, ext 2032), 1912 LTSR ended 18 Dec 2024 (ext 2029),
  XenDesktop 7.15 LTSR ended 15 Aug 2022 (ext 15 Aug 2027).
* **Citrix on-premises file-based licensing reached end of life 15 Apr 2026** — the License Activation Service is now
  the only way to activate or re-license. Minimum LAS-capable NetScaler builds: **14.1-51.x** and **13.1-60.x**.
* **NetScaler firmware lifecycle** — NetScaler ADC firmware release cycle (support.citrix.com CTX241500): a 7-year
  cycle applies from 14.1 onward. **13.1 end of maintenance 15 Sep 2026, end of life 15 Sep 2027**; 14.1 end of life
  8 Aug 2030; 13.0 and earlier are past end of life.
* **NITRO REST** — `/nitro/v1/config/<object>` and `/nitro/v1/stat/<object>`, session auth via the `login` object
  (developer-docs.netscaler.com); `lbvserver`, `sslvserver`, `sslcertkey`, `vpnvserver` confirmed from that reference.
* **CVAD PowerShell SDK** — `Get-BrokerSite`, `Get-BrokerController`, `Get-BrokerCatalog`, `Get-BrokerDesktopGroup`,
  `Get-BrokerMachine` (which supersedes the deprecated `Get-BrokerDesktop`) — Citrix developer documentation.
* **NPS** — the `Nps` module provides only `Export-NpsConfiguration` / `Import-NpsConfiguration`, and Microsoft Learn
  states plainly that the exported file **contains unencrypted shared secrets for RADIUS clients and members of remote
  RADIUS server groups**; `netsh nps export` requires `exportPSK=YES` for the same reason. This is what drives the
  redaction design above.
* **DHCP** — `Get-DhcpServerInDC`, `Get-DhcpServerv4Scope`, `Get-DhcpServerv4ScopeStatistics`, `Get-DhcpServerv4Failover`,
  `Get-DhcpServerv4OptionValue`, `Get-DhcpServerv4DnsSetting`, `Get-DhcpServerDnsCredential`, `Get-DhcpServerSetting`,
  `Get-DhcpServerAuditLog`, `Get-DhcpServerDatabase` — Microsoft Learn DhcpServer module reference.

## Version

1.2 — 8 Sep 2026 — added five collectors: `Dhcp`, `Nps`, `Citrix` (CVAD on-prem, beta), `NetScaler` (NITRO, beta) and
`ParallelsRas`. Added **one control, SRV-14** (published application / VDI platform), taking the review to 125 controls —
so the workbook goes to v1.2 and both Word deliverables to v1.1; every other new finding reports against existing
control IDs. **NET-07** and **NET-11** move from fully manual to partly automated on the back of the NPS collector,
which is the first evidence the toolkit has produced for 802.1X and network access control. DHCP moved out of the AD
collector into its own, gaining option hygiene, the DNS registration credential, name protection, audit logging,
database backup and conflict detection; the AD collector keeps DNS and time and says so when the DHCP collector has not
run into the same folder. SRV-12 narrows to print, RDS and legacy runtimes now that Citrix and RAS have SRV-14. Three
new lifecycle tables in `lib/CER.Common.ps1` for Parallels RAS, CVAD and NetScaler, all verified 8 Sep 2026, plus the
Citrix file-based-licensing end-of-life date (15 Apr 2026) as a finding in its own right. The NPS collector exports and
parses on the NPS server and redacts every RADIUS shared secret before anything is persisted — see the section above.
Coverage moves from 60/35/29 to **61 full, 37 partial, 27 manual**.

1.1 — 8 Sep 2026 — added the `ExchangeOnPrem` collector (on-prem / hybrid Exchange) against the existing 124 controls;
shared `Get-CERExchangeSupport` lifecycle helper; fixed the run-folder fork that let a standalone collector write into a
run folder the evidence pack never merged, with orphan-run detection and an Evidence-by-collector view to make it
visible; normalised evidence JSON on load so a PowerShell 5.1 round-trip can no longer collapse a collector's rows into
one entry that matches every control; rebuilt `summary.html` — filter/search toolbar, evidence split into labelled facts
with progressive disclosure, print stylesheet, still a single self-contained file. Trimmed the `repadmin /showbackup`
evidence line, which was dumping raw dSASignature GUIDs into the report. Added justification and recommendation to every
finding: `Why it matters` and `Target state` synced from the workbook Checklist by `build\Sync-CERControlText.ps1`, and a
per-finding `-Action` on 214 of the 215 evidence lines across all twelve collectors.

1.0 — 5 Sep 2026 — initial release. blueAPACHE Portfolio Engineering (Bikash Shrestha). Internal tool; not for distribution to clients.
