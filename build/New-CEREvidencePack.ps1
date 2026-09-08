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
$RunDir = (Resolve-Path -LiteralPath $RunDir).ProviderPath   # full path, so the merge commands below are copy-pasteable
$RunId = Split-Path $RunDir -Leaf; $Client = Split-Path (Split-Path $RunDir -Parent) -Leaf
$map = Get-Content -LiteralPath (Join-Path $root 'mapping/controls-map.json') -Raw -Encoding UTF8 | ConvertFrom-Json
function Expand-CEREvidence {
    <#
      Normalises one deserialised evidence entry into 1..n flat rows.

      Windows PowerShell 5.1 and PowerShell 7 do not always agree on how an array of objects
      round-trips through ConvertTo-Json / ConvertFrom-Json: a file written on a DC under 5.1 can come
      back as a SINGLE object whose Control/Flag/Evidence/Collector properties are parallel arrays.
      Left alone that is poison, because `$_.Control -eq 'IAM-10'` against an array returns the matching
      elements rather than $false - so one collapsed entry matches EVERY control and the report repeats
      the same wall of text under all of them (seen on RasLab, 8 Sep 2026).

      So: never trust the shape. If Control is a collection, unzip the parallel arrays back into rows;
      otherwise coerce each field to a scalar string. Anything that cannot be read is dropped.
    #>
    param($Entry)
    if ($null -eq $Entry) { return }
    $ctrl = $Entry.Control
    if ($null -eq $ctrl) { return }
    $props = 'Control', 'Flag', 'Evidence', 'Action', 'Source', 'Collector', 'Timestamp'
    if ($ctrl -is [string] -or $ctrl -isnot [System.Collections.IEnumerable]) {
        $o = [ordered]@{}
        foreach ($p in $props) { $v = $Entry.$p; $o[$p] = if ($null -eq $v) { '' } else { "$v" } }
        [pscustomobject]$o
        return
    }
    $n = @($ctrl).Count
    for ($i = 0; $i -lt $n; $i++) {
        $o = [ordered]@{}
        foreach ($p in $props) {
            $v = $Entry.$p
            if ($null -eq $v) { $o[$p] = ''; continue }
            if ($v -isnot [string] -and $v -is [System.Collections.IEnumerable]) {
                $a = @($v); $o[$p] = if ($i -lt $a.Count) { "$($a[$i])" } elseif ($a.Count -eq 1) { "$($a[0])" } else { '' }
            } else { $o[$p] = "$v" }
        }
        [pscustomobject]$o
    }
}

$evidence = @(); $coverage = @(); $runinfo = @(); $collapsed = 0
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $RunDir 'evidence') -Filter '*.evidence.json' -ErrorAction SilentlyContinue) {
    try {
        foreach ($entry in @(Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)) {
            $out = @(Expand-CEREvidence -Entry $entry)
            if ($out.Count -gt 1) { $collapsed++ }
            $evidence += $out
        }
    } catch { Write-Warning "bad $($f.Name): $($_.Exception.Message)" }
}
if ($collapsed) { Write-Host ("Note: {0} evidence entr(ies) came back from JSON with array-valued fields (a PowerShell 5.1 round-trip quirk) and were unpacked into separate rows." -f $collapsed) -ForegroundColor DarkGray }
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $RunDir 'coverage') -Filter '*.coverage.json' -ErrorAction SilentlyContinue) { try { $coverage += @(Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $RunDir 'logs') -Filter '*.runinfo.json' -ErrorAction SilentlyContinue) { try { $runinfo += @(Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }
$evidence = @($evidence | Where-Object { $_ -and $_.Control })
$ran = @($runinfo | ForEach-Object { $_.Collector } | Select-Object -Unique)
if ($ran.Count -eq 0) { $ran = @($coverage | ForEach-Object { $_.Collector } | Select-Object -Unique) }
$flagRank = @{ Attention = 3; Unknown = 2; Info = 1; OK = 0 }
$failedSections = @($coverage | Where-Object { $_.Status -in 'Failed', 'NoAccess', 'NotLicensed', 'NotInstalled' })

# ---------------- did anything run but not reach this pack?
# Two failure modes used to be silent: a collector that ran here but contributed no evidence, and a
# collector that ran into a DIFFERENT run folder for the same client (an omitted -RunId used to fork one).
$byCollector = @($evidence | Group-Object Collector | ForEach-Object {
        $name = $_.Name; $rows = @($_.Group)
        [pscustomobject][ordered]@{
            Collector = $name; EvidenceRows = $rows.Count
            Controls  = @($rows | ForEach-Object { $_.Control } | Select-Object -Unique).Count
            Attention = @($rows | Where-Object { $_.Flag -eq 'Attention' }).Count
            Sections  = @($coverage | Where-Object { $_.Collector -eq $name }).Count
        }
    } | Sort-Object Collector)
$silent = @($ran | Where-Object { $c = $_; -not @($evidence | Where-Object { $_.Collector -eq $c }).Count } | Sort-Object)
$clientDir = Split-Path $RunDir -Parent
$orphans = @()
foreach ($d in @(Get-ChildItem -LiteralPath $clientDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $RunId })) {
    $cols = @(); $n = 0
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $d.FullName 'evidence') -Filter '*.evidence.json' -ErrorAction SilentlyContinue) {
        try {
            $j = @(Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { Expand-CEREvidence -Entry $_ })
            if ($j.Count) { $n += $j.Count; $cols += @($j | ForEach-Object { $_.Collector } | Select-Object -Unique) }
        } catch { }
    }
    if ($n -gt 0) { $orphans += [pscustomobject]@{ RunId = $d.Name; Rows = $n; Collectors = (($cols | Select-Object -Unique | Sort-Object) -join ', '); Path = $d.FullName } }
}
foreach ($o in $orphans) {
    Write-Warning ("Run folder {0} for {1} holds {2} evidence rows ({3}) that are NOT in this pack. If that is part of the same review, merge it and rebuild:" -f $o.RunId, $Client, $o.Rows, $o.Collectors)
    Write-Host ("    Copy-Item -Path '{0}\*' -Destination '{1}' -Recurse -Force" -f $o.Path, $RunDir) -ForegroundColor Yellow
    Write-Host ("    .\build\New-CEREvidencePack.ps1 -RunDir '{0}'" -f $RunDir) -ForegroundColor Yellow
}
if ($silent.Count) { Write-Warning ("Collector(s) ran in this folder but produced no evidence rows: {0}. See coverage.md for the failed sections." -f ($silent -join ', ')) }

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
    # Recommended actions, worst flag first, de-duplicated - several findings on one control often earn the
    # same next step, and repeating it in the report just buries the ones that differ.
    $acts = @($ev | Where-Object { "$($_.Action)".Trim() } | ForEach-Object { "$($_.Action)".Trim() } | Select-Object -Unique)
    [pscustomobject][ordered]@{
        ID = $m.id; Domain = $m.domain; Control = $m.control; AutoCoverage = $m.auto; Status = $status; Flag = $flag
        Evidence = ($lines -join "`n"); EvidenceCount = $ev.Count; Collectors = (($ev | ForEach-Object { $_.Collector } | Select-Object -Unique) -join ', ')
        WhyItMatters = "$($m.why)"; TargetState = "$($m.target)"; RecommendedActions = ($acts -join "`n")
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
$null = $sb.AppendLine(""); $null = $sb.AppendLine("## Evidence by collector"); $null = $sb.AppendLine("")
$null = $sb.AppendLine("The review has no per-collector domain - AD, Exchange and the rest feed the 11 workbook domains, so a"); $null = $sb.AppendLine("collector's contribution is only visible here. A collector missing from this table produced nothing.")
$null = $sb.AppendLine(""); $null = $sb.AppendLine("| Collector | Evidence rows | Controls touched | Attention | Sections |"); $null = $sb.AppendLine("|---|---|---|---|---|")
foreach ($b in $byCollector) { $null = $sb.AppendLine(("| {0} | {1} | {2} | {3} | {4} |" -f $b.Collector, $b.EvidenceRows, $b.Controls, $b.Attention, $b.Sections)) }
if ($silent.Count) { $null = $sb.AppendLine(""); $null = $sb.AppendLine(("**Ran but contributed nothing:** {0}. Check the failed sections below and `logs\<collector>.log`." -f ($silent -join ', '))) }
if ($orphans.Count) {
    $null = $sb.AppendLine(""); $null = $sb.AppendLine("### Evidence found outside this run folder"); $null = $sb.AppendLine("")
    $null = $sb.AppendLine("These run folders under the same client hold evidence that is **not** in this pack - the usual cause is a")
    $null = $sb.AppendLine("collector run on its own without ``-RunId``. Merge and rebuild if they belong to this review.")
    $null = $sb.AppendLine(""); $null = $sb.AppendLine("| Run folder | Rows | Collectors |"); $null = $sb.AppendLine("|---|---|---|")
    foreach ($o in $orphans) { $null = $sb.AppendLine(("| {0} | {1} | {2} |" -f $o.RunId, $o.Rows, $o.Collectors)) }
    $null = $sb.AppendLine(""); $null = $sb.AppendLine('```powershell')
    foreach ($o in $orphans) { $null = $sb.AppendLine(("Copy-Item -Path '{0}\*' -Destination '{1}' -Recurse -Force" -f $o.Path, $RunDir)) }
    $null = $sb.AppendLine((".\build\New-CEREvidencePack.ps1 -RunDir '{0}'" -f $RunDir)); $null = $sb.AppendLine('```')
}
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
function _slug { param($s) return (("$s" -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLower()) }

function _seg {
    <# Collector evidence is written as "Label: value; Label: value; ..." - factual but long. Split it on
       semicolons so the reader gets a scannable list of facts instead of a 700-character paragraph. #>
    param([string]$Text)
    $t = "$Text".Trim()
    if (-not $t) { return @() }
    $parts = @($t -split ';\s+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($parts.Count -le 1) { return @($t) }
    return $parts
}
function _kv {
    <# Pull the "Label:" off the front of a segment so labels and values can be styled apart. #>
    param([string]$Seg)
    $m = [regex]::Match($Seg, '^([A-Za-z0-9 /()\.\-]{2,48}?):\s+(.+)$')
    if ($m.Success) { return '<span class="k">' + (_h $m.Groups[1].Value) + '</span><span class="v">' + (_h $m.Groups[2].Value) + '</span>' }
    return '<span class="v">' + (_h $Seg) + '</span>'
}
function _evli {
    <# One evidence row: flag chip, collector, the first few facts, the rest behind a disclosure, then the
       recommended action for THIS finding if the collector wrote one. #>
    param($Row, [int]$Show = 4)
    $segs = @(_seg $Row.Evidence)
    $head = @($segs | Select-Object -First $Show)
    $tail = @($segs | Select-Object -Skip $Show)
    $s = '<li class="ev" data-flag="' + (_h $Row.Flag) + '">'
    $s += '<div class="evhead"><span class="chip ' + (_h $Row.Flag) + '">' + (_h $Row.Flag) + '</span><span class="src">' + (_h $Row.Collector) + '</span></div>'
    $s += '<ul class="facts">' + (($head | ForEach-Object { '<li>' + (_kv $_) + '</li>' }) -join '') + '</ul>'
    if ($tail.Count) {
        $s += '<details><summary>' + $tail.Count + ' more</summary><ul class="facts">' + (($tail | ForEach-Object { '<li>' + (_kv $_) + '</li>' }) -join '') + '</ul></details>'
    }
    $act = "$($Row.Action)".Trim()
    if ($act) { $s += '<div class="act"><b>Recommended</b>' + (_h $act) + '</div>' }
    return $s + '</li>'
}
function _rationale {
    <# The control-level justification and baseline, quoted from the review workbook's Checklist. #>
    param($Row, [switch]$Compact)
    $w = "$($Row.WhyItMatters)".Trim(); $t = "$($Row.TargetState)".Trim()
    if (-not $w -and -not $t) { return '' }
    $inner = ''
    if ($w) { $inner += '<p class="why"><b>Why it matters</b>' + (_h $w) + '</p>' }
    if ($t) { $inner += '<p class="why tgt"><b>Target state</b>' + (_h $t) + '</p>' }
    if ($Compact) { return '<details class="rat"><summary>Why / target</summary>' + $inner + '</details>' }
    return '<div class="rat">' + $inner + '</div>'
}

$css = @'
:root{--ink:#101828;--mut:#667085;--line:#e4e7ec;--bg:#f7f8fa;--card:#fff;--brand:#1f3864;
--att:#b42318;--attbg:#fef3f2;--attbd:#fecdca;--ok:#067647;--okbg:#ecfdf3;--okbd:#abefc6;
--info:#175cd3;--infobg:#eff8ff;--infobd:#b2ddff;--unk:#475467;--unkbg:#f2f4f7;--unkbd:#e4e7ec}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px 64px}
header{background:var(--brand);color:#fff;padding:20px 0 18px;margin-bottom:18px}
header .wrap{padding-bottom:0}
h1{margin:0 0 4px;font-size:20px;font-weight:600;letter-spacing:-.2px}
.meta{font-size:13px;opacity:.9}.meta b{font-weight:600}
.warn{font-size:12px;opacity:.8;margin-top:8px;max-width:760px}
h2{font-size:16px;margin:34px 0 10px;padding-bottom:7px;border-bottom:2px solid var(--brand);color:var(--brand)}
h3{font-size:14px;margin:22px 0 8px;color:var(--brand)}
.kpis{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 6px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:104px}
.kpi b{display:block;font-size:21px;line-height:1.2;color:var(--brand)}
.kpi span{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px}
.kpi.hot b{color:var(--att)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:2px 16px 14px;margin-bottom:14px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
th{background:#f2f4f7;color:#344054;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.4px;padding:8px 10px;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:2}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:#fcfcfd}
.num{text-align:right;font-variant-numeric:tabular-nums}
.cid{font-weight:600;white-space:nowrap}
.ctitle{color:var(--mut);font-size:12px;display:block;margin-top:2px}
.chip{display:inline-block;padding:1px 8px;border-radius:11px;font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;border:1px solid}
.chip.Attention{color:var(--att);background:var(--attbg);border-color:var(--attbd)}
.chip.OK{color:var(--ok);background:var(--okbg);border-color:var(--okbd)}
.chip.Info{color:var(--info);background:var(--infobg);border-color:var(--infobd)}
.chip.Unknown{color:var(--unk);background:var(--unkbg);border-color:var(--unkbd)}
.st{display:inline-block;font-size:11.5px;font-weight:600;white-space:nowrap}
.st-Collected{color:var(--ok)}.st-Partial{color:#b54708}.st-Notcollected{color:var(--att)}
.st-Notrun{color:var(--mut)}.st-Manual{color:var(--unk)}
ul.evs{list-style:none;margin:0;padding:0}
li.ev{padding:9px 0;border-top:1px dashed var(--line)}
li.ev:first-child{border-top:0;padding-top:2px}
.evhead{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.src{font-size:10.5px;color:var(--mut);font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
ul.facts{list-style:none;margin:0;padding:0}
ul.facts li{padding:2px 0 2px 12px;position:relative;font-size:12.5px}
ul.facts li:before{content:"";position:absolute;left:0;top:10px;width:4px;height:4px;border-radius:50%;background:#cbd2dc}
.k{color:var(--mut);margin-right:5px}
.k:after{content:":"}
.v{color:var(--ink)}
details{margin-top:4px}
summary{cursor:pointer;font-size:11.5px;color:var(--info);width:fit-content}
summary:hover{text-decoration:underline}
.act{margin:7px 0 2px;padding:7px 11px;background:#f5f8ff;border-left:3px solid var(--info);border-radius:0 6px 6px 0;font-size:12.5px;color:#1d2939}
.act b{display:block;color:var(--info);font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px;font-weight:700}
.rat{margin:6px 0 2px}
p.why{margin:0 0 5px;font-size:12px;color:#475467;line-height:1.5}
p.why b{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#98a2b3;font-weight:700;margin-bottom:1px}
p.why.tgt{color:#344054}
details.rat>summary{font-size:11px;color:var(--mut)}
details.rat[open]{margin-top:6px}
.manual{color:var(--mut);font-size:12px}
.small{color:var(--mut);font-size:12px}
.note{color:var(--mut);font-size:11.5px;display:block;margin-top:3px}
.banner{border-radius:8px;padding:11px 14px;font-size:13px;margin:12px 0;border:1px solid}
.banner.bad{background:var(--attbg);border-color:var(--attbd);color:#912018}
.banner.info{background:var(--infobg);border-color:var(--infobd);color:#194185}
.banner code{background:rgba(0,0,0,.05);padding:1px 5px;border-radius:4px;font-size:12px}
.bar{position:sticky;top:0;z-index:9;background:rgba(247,248,250,.94);backdrop-filter:blur(6px);
border-bottom:1px solid var(--line);padding:10px 0;margin:0 -20px 6px;padding-left:20px;padding-right:20px;
display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.bar input{flex:1 1 220px;min-width:180px;padding:7px 11px;border:1px solid var(--line);border-radius:7px;font-size:13px;background:#fff}
.bar button{padding:6px 12px;border:1px solid var(--line);border-radius:7px;background:#fff;font-size:12px;cursor:pointer;color:#344054}
.bar button.on{background:var(--brand);color:#fff;border-color:var(--brand)}
.bar .sep{color:var(--line)}
.jump{font-size:12px;margin:10px 0 0}
.jump a{color:var(--info);text-decoration:none;margin-right:12px;white-space:nowrap}
.jump a:hover{text-decoration:underline}
.hide{display:none!important}
footer{margin-top:34px;padding-top:14px;border-top:1px solid var(--line);color:var(--mut);font-size:11.5px}
@media print{
 body{background:#fff}.bar,.jump{display:none}details{display:block}details summary{display:none}
 .card{break-inside:avoid;border:0;padding:0}th{position:static}h2{page-break-after:avoid}
}
'@

$js = @'
(function(){
 var q=document.getElementById("q"), btns=[].slice.call(document.querySelectorAll("[data-filter]")), f="all";
 function apply(){
  var t=(q.value||"").toLowerCase();
  [].forEach.call(document.querySelectorAll("tr[data-row]"),function(r){
   var okF = (f==="all") || (r.getAttribute("data-flags")||"").indexOf(f)>-1;
   var okT = !t || (r.getAttribute("data-text")||"").indexOf(t)>-1;
   r.classList.toggle("hide", !(okF&&okT));
  });
  [].forEach.call(document.querySelectorAll("section[data-domain]"),function(s){
   var any=s.querySelectorAll("tr[data-row]:not(.hide)").length;
   s.classList.toggle("hide", any===0);
  });
 }
 q.addEventListener("input",apply);
 btns.forEach(function(b){b.addEventListener("click",function(){
  btns.forEach(function(x){x.classList.remove("on")}); b.classList.add("on"); f=b.getAttribute("data-filter"); apply();
 });});
 var ex=document.getElementById("expand"), open=false;
 ex.addEventListener("click",function(){
  open=!open; [].forEach.call(document.querySelectorAll("details"),function(d){d.open=open});
  ex.textContent = open ? "Collapse detail" : "Expand detail";
 });
})();
'@

$h = New-Object System.Text.StringBuilder
$null = $h.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
$null = $h.AppendLine('<title>CER discovery - ' + (_h $Client) + ' - ' + (_h $RunId) + '</title><style>' + $css + '</style></head><body>')
$null = $h.AppendLine('<header><div class="wrap"><h1>Client Environment Review - discovery evidence</h1>')
$null = $h.AppendLine('<div class="meta"><b>' + (_h $Client) + '</b> &nbsp;&middot;&nbsp; run ' + (_h $RunId) + ' &nbsp;&middot;&nbsp; generated ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + ' &nbsp;&middot;&nbsp; collectors: ' + (_h ($ran -join ', ')) + '</div>')
$null = $h.AppendLine('<div class="warn">Internal working output. Contains real names and hostnames - keep local, sanitise before it leaves. The tool reports what it saw; the score is the reviewer''s.</div></div></header>')
$null = $h.AppendLine('<div class="wrap">')

# KPIs
$null = $h.Append('<div class="kpis">')
foreach ($s in 'Collected', 'Partial', 'Not collected', 'Not run', 'Manual') { $null = $h.Append('<div class="kpi"><b>' + @($rows | Where-Object { $_.Status -eq $s }).Count + '</b><span>' + (_h $s) + '</span></div>') }
$null = $h.Append('<div class="kpi hot"><b>' + $att.Count + '</b><span>Attention</span></div>')
$null = $h.AppendLine('</div>')

if ($silent.Count) { $null = $h.AppendLine('<div class="banner bad"><b>Ran but produced no evidence:</b> ' + (_h ($silent -join ', ')) + '. The collector executed and wrote nothing - see Collector coverage at the foot of this page, and <code>logs\' + '&lt;collector&gt;.log</code>.</div>') }
if ($orphans.Count) {
    $null = $h.Append('<div class="banner bad"><b>Evidence exists outside this run folder and is not in this pack.</b> Usually a collector run on its own without <code>-RunId</code>. ')
    $null = $h.Append((@($orphans | ForEach-Object { (_h $_.RunId) + ' (' + $_.Rows + ' rows: ' + (_h $_.Collectors) + ')' }) -join '; '))
    $null = $h.AppendLine('. Merge those folders into this one and rebuild - the console output prints the exact commands.</div>')
}

# ---- toolbar
$null = $h.AppendLine('<div class="bar"><input id="q" type="search" placeholder="Filter controls, evidence, hostnames...">' +
    '<span class="sep">|</span><button data-filter="all" class="on">All</button><button data-filter="Attention">Attention</button>' +
    '<button data-filter="OK">OK</button><button data-filter="Info">Info</button><button data-filter="Unknown">Unknown</button>' +
    '<span class="sep">|</span><button id="expand">Expand detail</button></div>')

$domains = @($rows | Select-Object -ExpandProperty Domain -Unique)
$null = $h.Append('<div class="jump"><b class="small">Jump to:</b> <a href="#attention">Attention</a>')
foreach ($d in $domains) { $null = $h.Append('<a href="#d-' + (_slug $d) + '">' + (_h $d) + '</a>') }
$null = $h.AppendLine('<a href="#coverage">Coverage</a></div>')

# ---- Attention findings
$null = $h.AppendLine('<h2 id="attention">Attention findings</h2>')
if ($att.Count) {
    $null = $h.AppendLine('<p class="small">Attention means the numbers deserve a look, not that the control fails. <b>Why it matters</b> and <b>Target state</b> are quoted from the review workbook''s Checklist; <b>Recommended</b> is written against the specific finding and is a starting point to tailor, not a decision.</p>')
    $null = $h.AppendLine('<div class="card"><table><thead><tr><th style="width:280px">Control</th><th>What was found and what to do</th></tr></thead><tbody>')
    foreach ($r in $att) {
        $evs = @($evidence | Where-Object { $_.Control -eq $r.ID -and $_.Flag -eq 'Attention' })
        $txt = ((@($r.ID, $r.Control, $r.Domain, $r.WhyItMatters, $r.TargetState) + @($evs | ForEach-Object { $_.Evidence }) + @($evs | ForEach-Object { $_.Action })) -join ' ').ToLower()
        $null = $h.AppendLine('<tr data-row data-flags="Attention" data-text="' + (_h $txt) + '">' +
            '<td><span class="cid">' + (_h $r.ID) + '</span><span class="ctitle">' + (_h $r.Domain) + '</span><span class="ctitle">' + (_h $r.Control) + '</span>' + (_rationale $r) + '</td>' +
            '<td><ul class="evs">' + ((@($evs | ForEach-Object { _evli $_ })) -join '') + '</ul></td></tr>')
    }
    $null = $h.AppendLine('</tbody></table></div>')
} else { $null = $h.AppendLine('<div class="banner info">No Attention findings in this run. That is only meaningful for the controls that were actually collected - check the counts above.</div>') }

# ---- All controls, by domain
$null = $h.AppendLine('<h2>All controls by domain</h2>')
foreach ($d in $domains) {
    $null = $h.AppendLine('<section data-domain id="d-' + (_slug $d) + '"><h3>' + (_h $d) + '</h3><div class="card"><table><thead><tr><th style="width:78px">ID</th><th style="width:250px">Control</th><th style="width:104px">Status</th><th>Tool evidence</th><th style="width:230px">Where to find the rest</th></tr></thead><tbody>')
    foreach ($r in ($rows | Where-Object { $_.Domain -eq $d })) {
        $evs = @($evidence | Where-Object { $_.Control -eq $r.ID } | Sort-Object { - $flagRank[$_.Flag] })
        $flags = (@($evs | ForEach-Object { $_.Flag } | Select-Object -Unique) -join ' ')
        $txt = ((@($r.ID, $r.Control, $r.Status, $r.WhyItMatters, $r.TargetState) + @($evs | ForEach-Object { $_.Evidence }) + @($evs | ForEach-Object { $_.Action })) -join ' ').ToLower()
        $body = if ($evs.Count) { '<ul class="evs">' + ((@($evs | ForEach-Object { _evli $_ })) -join '') + '</ul>' } else { '<span class="manual">no automated evidence</span>' }
        $st = '<span class="st st-' + ($r.Status -replace '[^A-Za-z]', '') + '">' + (_h $r.Status) + '</span>'
        if ($r.Note -and $r.Status -ne 'Manual') { $st += '<span class="note">' + (_h $r.Note) + '</span>' }
        $null = $h.AppendLine('<tr data-row data-flags="' + (_h $flags) + '" data-text="' + (_h $txt) + '">' +
            '<td><span class="cid">' + (_h $r.ID) + '</span><span class="ctitle">' + (_h $r.AutoCoverage) + '</span></td>' +
            '<td>' + (_h $r.Control) + (_rationale $r -Compact) + '</td><td>' + $st + '</td><td>' + $body + '</td><td class="manual">' + (_h $r.ManualSource) + '</td></tr>')
    }
    $null = $h.AppendLine('</tbody></table></div></section>')
}

# ---- Evidence by collector. The review has no per-collector domain, so this is the only place a
# collector's own contribution is visible - without it a collector that ran and produced nothing looks
# identical to one that was never run.
$null = $h.AppendLine('<h2 id="bycollector">Evidence by collector</h2>')
$null = $h.AppendLine('<p class="small">Findings are filed under the review domains above, never by collector - so this is the only view of what each collector actually contributed. A collector that ran but is absent here produced nothing.</p>')
$null = $h.AppendLine('<div class="card"><table><thead><tr><th style="width:150px">Collector</th><th class="num" style="width:96px">Rows</th><th class="num" style="width:96px">Controls</th><th class="num" style="width:96px">Attention</th><th>Controls touched</th></tr></thead><tbody>')
foreach ($b in $byCollector) {
    $ids = @($evidence | Where-Object { $_.Collector -eq $b.Collector } | ForEach-Object { $_.Control } | Select-Object -Unique | Sort-Object)
    $null = $h.AppendLine('<tr><td><b>' + (_h $b.Collector) + '</b></td><td class="num">' + $b.EvidenceRows + '</td><td class="num">' + $b.Controls + '</td>' +
        '<td class="num">' + $(if ($b.Attention) { '<span class="chip Attention">' + $b.Attention + '</span>' } else { '0' }) + '</td><td class="small">' + (_h ($ids -join ', ')) + '</td></tr>')
}
$null = $h.AppendLine('</tbody></table></div>')
$null = $h.AppendLine('<h2 id="coverage">Collector coverage</h2>')
$null = $h.AppendLine('<p class="small">Every section each collector attempted, and why any of them came back empty. 403 means role or consent, NotLicensed means the P1/P2/Defender SKU is absent, NotInstalled means a missing module.</p>')
$null = $h.AppendLine('<div class="card"><table><thead><tr><th style="width:130px">Collector</th><th style="width:190px">Section</th><th style="width:110px">Status</th><th>Note</th><th style="width:120px">Host</th></tr></thead><tbody>')
foreach ($c in ($coverage | Sort-Object Collector, Section)) {
    $cls = if ($c.Status -eq 'Collected') { 'OK' } elseif ($c.Status -eq 'Partial') { 'Info' } elseif ($c.Status -eq 'Skipped') { 'Unknown' } else { 'Attention' }
    $null = $h.AppendLine('<tr><td>' + (_h $c.Collector) + '</td><td class="small">' + (_h $c.Section) + '</td><td><span class="chip ' + $cls + '">' + (_h $c.Status) + '</span></td><td class="small">' + (_h $c.Note) + '</td><td class="small">' + (_h $c.Host) + '</td></tr>')
}
$null = $h.AppendLine('</tbody></table></div>')
$null = $h.AppendLine('<footer>CER-Discovery v1.1 &middot; blueAPACHE Portfolio Engineering &middot; control map: mapping/controls-map.json &middot; raw collector output: raw\ &middot; workbook paste: AutoEvidence.csv</footer>')
$null = $h.AppendLine('</div><script>' + $js + '</script></body></html>')
$h.ToString() | Set-Content -LiteralPath (Join-Path $RunDir 'summary.html') -Encoding UTF8

[ordered]@{ Client = $Client; RunId = $RunId; Generated = (Get-Date).ToString('s'); Collectors = $ran; ByCollector = $byCollector; SilentCollectors = $silent; OrphanRuns = @($orphans | Select-Object RunId, Rows, Collectors); Controls = $rows.Count; Collected = @($rows | Where-Object { $_.Status -eq 'Collected' }).Count; Partial = @($rows | Where-Object { $_.Status -eq 'Partial' }).Count; NotCollected = @($rows | Where-Object { $_.Status -eq 'Not collected' }).Count; NotRun = @($rows | Where-Object { $_.Status -eq 'Not run' }).Count; Manual = @($rows | Where-Object { $_.Status -eq 'Manual' }).Count; Attention = $att.Count; EvidenceRows = $evidence.Count } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunDir 'pack.json') -Encoding UTF8
Write-Host ("Evidence pack written to {0}: evidence.csv, AutoEvidence.csv, coverage.md, summary.html  ({1} controls: {2} collected, {3} partial, {4} not collected, {5} not run, {6} manual; {7} with Attention)" -f $RunDir, $rows.Count, @($rows | Where-Object { $_.Status -eq 'Collected' }).Count, @($rows | Where-Object { $_.Status -eq 'Partial' }).Count, @($rows | Where-Object { $_.Status -eq 'Not collected' }).Count, @($rows | Where-Object { $_.Status -eq 'Not run' }).Count, @($rows | Where-Object { $_.Status -eq 'Manual' }).Count, $att.Count)
