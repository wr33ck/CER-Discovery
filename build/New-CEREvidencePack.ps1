#Requires -Version 5.1
<#
.SYNOPSIS
  Merges every collector's evidence and coverage in a run folder into:
    evidence.csv      - one row per control (status, flag, evidence lines, where to find the rest)
    AutoEvidence.csv  - same, in the column order of the workbook's AutoEvidence tab (paste from A2)
    coverage.md       - what ran, what failed and why, what is manual and where to look
    summary.html      - readable report (Attention items first, then every control by domain)
.EXAMPLE
  .\New-CEREvidencePack.ps1 -Client C-003 -OutputRoot D:\CER\output            # latest run for the client
  .\New-CEREvidencePack.ps1 -RunDir D:\CER\output\C-003\20260905-0900
#>
[CmdletBinding()]
param([string]$Client, [string]$OutputRoot, [string]$RunId, [string]$RunDir)
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib/CER.Common.ps1')
if (-not $RunDir) {
    if (-not $Client) { throw 'Give -RunDir or -Client (+ -OutputRoot / -RunId)' }
    if (-not $OutputRoot) { $OutputRoot = Join-Path (Get-Location).Path 'output' }
    $clientDir = Join-Path $OutputRoot $Client
    if ($RunId) { $RunDir = Join-Path $clientDir $RunId } else { $RunDir = (Get-ChildItem -LiteralPath $clientDir -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName }
}
if (-not (Test-Path -LiteralPath $RunDir)) { throw "Run folder not found: $RunDir" }
$RunId = Split-Path $RunDir -Leaf; $Client = Split-Path (Split-Path $RunDir -Parent) -Leaf
$map = Get-Content -LiteralPath (Join-Path $root 'mapping/controls-map.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$evidence = @(); $coverage = @(); $runinfo = @()
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $RunDir 'evidence') -Filter '*.evidence.json' -ErrorAction SilentlyContinue) { try { $evidence += @(Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { Write-Warning "bad $($f.Name)" } }
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $RunDir 'coverage') -Filter '*.coverage.json' -ErrorAction SilentlyContinue) { try { $coverage += @(Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $RunDir 'logs') -Filter '*.runinfo.json' -ErrorAction SilentlyContinue) { try { $runinfo += @(Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }
$evidence = @($evidence | Where-Object { $_ -and $_.Control })
$ran = @($runinfo | ForEach-Object { $_.Collector } | Select-Object -Unique)
if ($ran.Count -eq 0) { $ran = @($coverage | ForEach-Object { $_.Collector } | Select-Object -Unique) }
$flagRank = @{ Attention = 3; Unknown = 2; Info = 1; OK = 0 }
$failedSections = @($coverage | Where-Object { $_.Status -in 'Failed', 'NoAccess', 'NotLicensed', 'NotInstalled' })

$rows = foreach ($m in $map) {
    $ev = @($evidence | Where-Object { $_.Control -eq $m.id } | Sort-Object { - $flagRank[$_.Flag] })
    $real = @($ev | Where-Object { $_.Flag -ne 'Unknown' })
    $expected = @($m.collectors); $ranExpected = @($expected | Where-Object { $ran -contains $_ }); $missing = @($expected | Where-Object { $ran -notcontains $_ })
    $status = ''; $note = ''
    if ($m.auto -eq 'None') { $status = 'Manual' }
    elseif ($real.Count -gt 0) { $status = $(if ($m.auto -eq 'Full') { 'Collected' } else { 'Partial' }); if ($missing.Count) { $note = "Collector(s) not run: $($missing -join ', ')" } }
    elseif ($ev.Count -gt 0) { $status = 'Not collected'; $note = ($ev | ForEach-Object { $_.Evidence }) -join ' ' }
    elseif ($ranExpected.Count -eq 0) { $status = 'Not run'; $note = "Run collector(s): $($expected -join ', ')" }
    elseif ($missing.Count -gt 0) { $status = 'Not run'; $note = "Ran: $($ranExpected -join ', ') (nothing for this control); still to run: $($missing -join ', ')" }
    else { $status = 'Not collected'; $fs = @($failedSections | Where-Object { $ranExpected -contains $_.Collector }); $note = if ($fs.Count) { ($fs | ForEach-Object { "{0}/{1}: {2} - {3}" -f $_.Collector, $_.Section, $_.Status, $_.Note } | Select-Object -First 3) -join ' | ' } else { "Collector ran but produced no evidence for this control ($($ranExpected -join ', '))" } }
    $flag = if ($real.Count) { ($real | ForEach-Object { $_.Flag } | Sort-Object { - $flagRank[$_] } | Select-Object -First 1) } else { '' }
    $lines = @($ev | ForEach-Object { "[{0}|{1}] {2}" -f $_.Flag, $_.Collector, $_.Evidence })
    [pscustomobject][ordered]@{
        ID = $m.id; Domain = $m.domain; Control = $m.control; AutoCoverage = $m.auto; Status = $status; Flag = $flag
        Evidence = ($lines -join "`n"); EvidenceCount = $ev.Count; Collectors = (($ev | ForEach-Object { $_.Collector } | Select-Object -Unique) -join ', ')
        ToolGives = $m.gives; ManualSource = $m.manual; Note = $note; E8 = (($m.e8) -join ', '); TypicalTag = $m.tag; Run = $RunId; Client = $Client
    }
}
$rows | Export-Csv -LiteralPath (Join-Path $RunDir 'evidence.csv') -NoTypeInformation -Encoding UTF8
# workbook AutoEvidence tab order: ID | Status | Flag | Tool evidence | Where to find the rest | Collectors | Run
$rows | Select-Object ID, Status, Flag, @{ n = 'ToolEvidence'; e = { $_.Evidence } }, @{ n = 'WhereToFindTheRest'; e = { $_.ManualSource } }, Collectors, Run | Export-Csv -LiteralPath (Join-Path $RunDir 'AutoEvidence.csv') -NoTypeInformation -Encoding UTF8

# ---------------- coverage.md
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine("# CER-Discovery coverage - $Client - run $RunId")
$null = $sb.AppendLine(""); $null = $sb.AppendLine("Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm'). Collectors that ran: $($ran -join ', ')")
$null = $sb.AppendLine(""); $null = $sb.AppendLine("## Controls by status"); $null = $sb.AppendLine("")
$null = $sb.AppendLine("| Status | Count | Meaning |"); $null = $sb.AppendLine("|---|---|---|")
$meaning = @{ Collected = 'Automated evidence present; scoring still yours'; Partial = 'Automated evidence covers part of the control - see Where to find the rest'; 'Not collected' = 'A collector ran but this control got nothing (section failed / no access / not licensed) - see Note'; 'Not run' = 'The collector for this control was not executed in this run'; Manual = 'No automation in v1 - see Where to find the rest' }
foreach ($s in 'Collected', 'Partial', 'Not collected', 'Not run', 'Manual') { $null = $sb.AppendLine(("| {0} | {1} | {2} |" -f $s, @($rows | Where-Object { $_.Status -eq $s }).Count, $meaning[$s])) }
$att = @($rows | Where-Object { $_.Flag -eq 'Attention' })
$null = $sb.AppendLine(""); $null = $sb.AppendLine(("Controls with at least one **Attention** finding: {0}. Automated (Collected + Partial): {1} of {2}." -f $att.Count, @($rows | Where-Object { $_.Status -in 'Collected', 'Partial' }).Count, $rows.Count))
$null = $sb.AppendLine(""); $null = $sb.AppendLine("## Collector sections"); $null = $sb.AppendLine("")
$null = $sb.AppendLine("| Collector | Section | Status | Note |"); $null = $sb.AppendLine("|---|---|---|---|")
foreach ($c in ($coverage | Sort-Object Collector, Section)) { $null = $sb.AppendLine(("| {0} | {1} | {2} | {3} |" -f $c.Collector, $c.Section, $c.Status, (("$($c.Note)" -replace '\|', '/') -replace "[`r`n]+", ' '))) }
$null = $sb.AppendLine(""); $null = $sb.AppendLine("## Not collected / not run - what to do"); $null = $sb.AppendLine("")
foreach ($r in ($rows | Where-Object { $_.Status -in 'Not collected', 'Not run' })) { $null = $sb.AppendLine(("- **{0}** {1} - {2}. Manual fallback: {3}" -f $r.ID, $r.Control, $r.Note, $r.ManualSource)) }
$null = $sb.AppendLine(""); $null = $sb.AppendLine("## Manual controls - where to look"); $null = $sb.AppendLine("")
foreach ($r in ($rows | Where-Object { $_.Status -eq 'Manual' })) { $null = $sb.AppendLine(("- **{0}** {1} -> {2}" -f $r.ID, $r.Control, $r.ManualSource)) }
$null = $sb.AppendLine(""); $null = $sb.AppendLine("## Partial controls - what is still manual"); $null = $sb.AppendLine("")
foreach ($r in ($rows | Where-Object { $_.Status -eq 'Partial' })) { $null = $sb.AppendLine(("- **{0}** {1} -> {2}" -f $r.ID, $r.Control, $r.ManualSource)) }
$sb.ToString() | Set-Content -LiteralPath (Join-Path $RunDir 'coverage.md') -Encoding UTF8

# ---------------- summary.html
function _h { param($s) if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode("$s") }
$h = New-Object System.Text.StringBuilder
$null = $h.AppendLine('<!doctype html><html><head><meta charset="utf-8"><title>CER-Discovery ' + (_h $Client) + ' ' + (_h $RunId) + '</title><style>')
$null = $h.AppendLine('body{font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;margin:24px;max-width:1400px} h1{color:#1F3864} h2{color:#1F3864;border-bottom:2px solid #1F3864;padding-bottom:4px;margin-top:32px} h3{color:#2F5496;margin-bottom:4px} table{border-collapse:collapse;width:100%;margin:8px 0 16px} th{background:#1F3864;color:#fff;text-align:left;padding:6px 8px;font-size:12px} td{border-bottom:1px solid #ddd;padding:6px 8px;vertical-align:top} .Attention{background:#F8CBAD;font-weight:bold} .OK{background:#C6E0B4} .Info{background:#DDEBF7} .Unknown{background:#EDEDED} .pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;margin-right:4px} .ev{margin:0;padding-left:16px} .ev li{margin:2px 0} .manual{color:#595959;font-style:italic} .small{color:#595959;font-size:11px} .kpi{display:inline-block;border:1px solid #ccc;border-radius:6px;padding:8px 14px;margin:4px 8px 4px 0;background:#f7f7f7} .kpi b{font-size:20px;display:block;color:#1F3864}')
$null = $h.AppendLine('</style></head><body>')
$null = $h.AppendLine('<h1>Client Environment Review - discovery evidence</h1><p><b>Client:</b> ' + (_h $Client) + ' &nbsp; <b>Run:</b> ' + (_h $RunId) + ' &nbsp; <b>Generated:</b> ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + '<br><span class="small">Internal working output. Contains real names and hostnames - keep local; sanitise before it leaves. Scores are decided by the reviewer, not by this tool.</span></p>')
foreach ($s in 'Collected', 'Partial', 'Not collected', 'Not run', 'Manual') { $null = $h.Append('<div class="kpi"><b>' + @($rows | Where-Object { $_.Status -eq $s }).Count + '</b>' + (_h $s) + '</div>') }
$null = $h.Append('<div class="kpi"><b>' + $att.Count + '</b>Controls with Attention</div>')
$null = $h.AppendLine('<p class="small">Collectors that ran: ' + (_h ($ran -join ', ')) + '</p>')
$null = $h.AppendLine('<h2>Attention findings</h2><table><tr><th style="width:80px">Control</th><th style="width:170px">Domain</th><th>Evidence</th></tr>')
foreach ($r in $att) { $lines = @($evidence | Where-Object { $_.Control -eq $r.ID -and $_.Flag -eq 'Attention' } | ForEach-Object { '<li>' + (_h $_.Evidence) + ' <span class="small">[' + (_h $_.Collector) + ']</span></li>' }); $null = $h.AppendLine('<tr><td><b>' + (_h $r.ID) + '</b></td><td>' + (_h $r.Domain) + '<br><span class="small">' + (_h $r.Control) + '</span></td><td><ul class="ev">' + ($lines -join '') + '</ul></td></tr>') }
$null = $h.AppendLine('</table>')
$null = $h.AppendLine('<h2>All controls by domain</h2>')
foreach ($d in ($rows | Select-Object -ExpandProperty Domain -Unique)) {
    $null = $h.AppendLine('<h3>' + (_h $d) + '</h3><table><tr><th style="width:70px">ID</th><th style="width:260px">Control</th><th style="width:90px">Status</th><th>Tool evidence</th><th style="width:260px">Where to find the rest</th></tr>')
    foreach ($r in ($rows | Where-Object { $_.Domain -eq $d })) {
        $evs = @($evidence | Where-Object { $_.Control -eq $r.ID } | Sort-Object { - $flagRank[$_.Flag] } | ForEach-Object { '<li><span class="pill ' + $_.Flag + '">' + $_.Flag + '</span>' + (_h $_.Evidence) + ' <span class="small">[' + (_h $_.Collector) + ']</span></li>' })
        $st = $r.Status; if ($r.Note -and $st -ne 'Manual') { $st += '<br><span class="small">' + (_h $r.Note) + '</span>' }
        $null = $h.AppendLine('<tr><td><b>' + (_h $r.ID) + '</b><br><span class="small">' + (_h $r.AutoCoverage) + '</span></td><td>' + (_h $r.Control) + '</td><td>' + $st + '</td><td>' + $(if ($evs.Count) { '<ul class="ev">' + ($evs -join '') + '</ul>' } else { '<span class="manual">no automated evidence</span>' }) + '</td><td class="manual">' + (_h $r.ManualSource) + '</td></tr>')
    }
    $null = $h.AppendLine('</table>')
}
$null = $h.AppendLine('<h2>Collector coverage</h2><table><tr><th>Collector</th><th>Section</th><th>Status</th><th>Note</th><th>Host</th></tr>')
foreach ($c in ($coverage | Sort-Object Collector, Section)) { $cls = if ($c.Status -eq 'Collected') { 'OK' } elseif ($c.Status -eq 'Partial') { 'Info' } elseif ($c.Status -eq 'Skipped') { 'Unknown' } else { 'Attention' }; $null = $h.AppendLine('<tr><td>' + (_h $c.Collector) + '</td><td>' + (_h $c.Section) + '</td><td class="' + $cls + '">' + (_h $c.Status) + '</td><td>' + (_h $c.Note) + '</td><td class="small">' + (_h $c.Host) + '</td></tr>') }
$null = $h.AppendLine('</table><p class="small">CER-Discovery v1.0 - blueAPACHE Portfolio Engineering. Map: mapping/controls-map.json.</p></body></html>')
$h.ToString() | Set-Content -LiteralPath (Join-Path $RunDir 'summary.html') -Encoding UTF8

[ordered]@{ Client = $Client; RunId = $RunId; Generated = (Get-Date).ToString('s'); Collectors = $ran; Controls = $rows.Count; Collected = @($rows | Where-Object { $_.Status -eq 'Collected' }).Count; Partial = @($rows | Where-Object { $_.Status -eq 'Partial' }).Count; NotCollected = @($rows | Where-Object { $_.Status -eq 'Not collected' }).Count; NotRun = @($rows | Where-Object { $_.Status -eq 'Not run' }).Count; Manual = @($rows | Where-Object { $_.Status -eq 'Manual' }).Count; Attention = $att.Count; EvidenceRows = $evidence.Count } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunDir 'pack.json') -Encoding UTF8
Write-Host ("Evidence pack written to {0}: evidence.csv, AutoEvidence.csv, coverage.md, summary.html  ({1} controls: {2} collected, {3} partial, {4} not collected, {5} not run, {6} manual; {7} with Attention)" -f $RunDir, $rows.Count, @($rows | Where-Object { $_.Status -eq 'Collected' }).Count, @($rows | Where-Object { $_.Status -eq 'Partial' }).Count, @($rows | Where-Object { $_.Status -eq 'Not collected' }).Count, @($rows | Where-Object { $_.Status -eq 'Not run' }).Count, @($rows | Where-Object { $_.Status -eq 'Manual' }).Count, $att.Count)
