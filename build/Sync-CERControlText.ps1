#Requires -Version 5.1
<#
.SYNOPSIS
  Pulls the per-control "Why it matters" and "Target state" wording out of the review workbook's Checklist
  tab and writes it into mapping/controls-map.json as `why` and `target`.

.DESCRIPTION
  The workbook is the source of truth for that wording - it is what the reviewer reads and what goes in
  front of the client. The discovery tool should quote it, never keep a second copy that drifts. This
  script is how the copy in controls-map.json is refreshed after the workbook is edited.

  Reads the .xlsx directly as a zip of XML (System.IO.Compression) so it needs no Excel, no ImportExcel
  module and no Python - it has to run on a bA laptop and on a jump host.

  Read-only against the workbook. The only file written is mapping/controls-map.json.

.EXAMPLE
  .\build\Sync-CERControlText.ps1
  .\build\Sync-CERControlText.ps1 -Workbook 'D:\CER\Client-Environment-Review-Workbook-v1.2.xlsx' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Workbook,
    [string]$MapPath,
    [string]$Sheet = 'Checklist',
    [string]$IdColumn = 'ID',
    [string]$WhyColumn = 'Why it matters',
    [string]$TargetColumn = 'Target state'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $Workbook) {
    $Workbook = @(Get-ChildItem -LiteralPath (Join-Path $root 'deliverables') -Filter '*Workbook*.xlsx' -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)
    if (-not $Workbook) { throw 'No workbook found under deliverables\ - pass -Workbook.' }
}
if (-not $MapPath) { $MapPath = Join-Path $root 'mapping/controls-map.json' }
Write-Host ("Workbook: {0}" -f $Workbook) -ForegroundColor Cyan

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($Workbook)
try {
    function Get-Xml { param($Name)
        $entry = $zip.Entries | Where-Object { $_.FullName -eq $Name } | Select-Object -First 1
        if (-not $entry) { return $null }
        $sr = New-Object System.IO.StreamReader($entry.Open())
        try { return [xml]$sr.ReadToEnd() } finally { $sr.Dispose() }
    }

    # sheet name -> r:id -> target path
    $wbXml = Get-Xml 'xl/workbook.xml'
    $relXml = Get-Xml 'xl/_rels/workbook.xml.rels'
    $rid = $null
    foreach ($s in $wbXml.workbook.sheets.sheet) { if ($s.name -eq $Sheet) { $rid = $s.id; if (-not $rid) { $rid = $s.'r:id' } } }
    if (-not $rid) { throw ("Sheet '{0}' not found. Sheets: {1}" -f $Sheet, (($wbXml.workbook.sheets.sheet | ForEach-Object { $_.name }) -join ', ')) }
    $target = ($relXml.Relationships.Relationship | Where-Object { $_.Id -eq $rid } | Select-Object -First 1).Target
    $target = ($target -replace '^/xl/', '') -replace '^/', ''
    if ($target -notlike 'xl/*') { $target = 'xl/' + $target }

    # shared strings
    $shared = @()
    $ssXml = Get-Xml 'xl/sharedStrings.xml'
    if ($ssXml) {
        foreach ($si in $ssXml.sst.si) {
            if ($si.t -is [string]) { $shared += $si.t }
            elseif ($si.t.'#text') { $shared += $si.t.'#text' }
            else { $shared += (($si.r | ForEach-Object { if ($_.t -is [string]) { $_.t } else { $_.t.'#text' } }) -join '') }
        }
    }

    function Get-CellText { param($c)
        if ($null -eq $c) { return '' }
        if ($c.t -eq 's') { $i = [int]$c.v; if ($i -ge 0 -and $i -lt $shared.Count) { return "$($shared[$i])" }; return '' }
        if ($c.t -eq 'inlineStr') { return "$($c.is.t)" }
        if ($null -ne $c.v) { return "$($c.v)" }
        return ''
    }
    function Get-ColIndex { param([string]$Ref)   # 'BC12' -> 0-based column index
        $letters = ($Ref -replace '\d', '')
        $n = 0; foreach ($ch in $letters.ToCharArray()) { $n = $n * 26 + ([int][char]([string]$ch).ToUpper() - 64) }
        return $n - 1
    }

    $shXml = Get-Xml $target
    if (-not $shXml) { throw "Could not read sheet part $target" }
    $grid = @{}
    foreach ($row in $shXml.worksheet.sheetData.row) {
        $r = [int]$row.r; $cells = @{}
        foreach ($c in $row.c) { $cells[(Get-ColIndex $c.r)] = (Get-CellText $c) }
        $grid[$r] = $cells
    }

    # find the header row: the one carrying the ID column and the two text columns
    $hdrRow = 0; $cId = -1; $cWhy = -1; $cTgt = -1
    foreach ($r in ($grid.Keys | Sort-Object)) {
        $cells = $grid[$r]
        $i = -1; $w = -1; $t = -1
        foreach ($k in $cells.Keys) {
            $v = "$($cells[$k])".Trim()
            if ($v -eq $IdColumn) { $i = $k }
            elseif ($v -like ($WhyColumn + '*')) { $w = $k }
            elseif ($v -like ($TargetColumn + '*')) { $t = $k }
        }
        if ($i -ge 0 -and $w -ge 0 -and $t -ge 0) { $hdrRow = $r; $cId = $i; $cWhy = $w; $cTgt = $t; break }
    }
    if (-not $hdrRow) { throw ("Could not find a header row containing '{0}', '{1}*' and '{2}*' on sheet '{3}'." -f $IdColumn, $WhyColumn, $TargetColumn, $Sheet) }
    Write-Host ("Header row {0}: ID=col {1}, '{2}'=col {3}, '{4}'=col {5}" -f $hdrRow, $cId, $WhyColumn, $cWhy, $TargetColumn, $cTgt)

    $text = @{}
    foreach ($r in ($grid.Keys | Where-Object { $_ -gt $hdrRow } | Sort-Object)) {
        $cells = $grid[$r]
        $id = "$($cells[$cId])".Trim()
        if (-not $id -or $id -notmatch '^[A-Z0-9]{2,5}-\d{2}$') { continue }
        $text[$id] = @{ why = ("$($cells[$cWhy])" -replace '\s+', ' ').Trim(); target = ("$($cells[$cTgt])" -replace '\s+', ' ').Trim() }
    }
    Write-Host ("Read wording for {0} controls." -f $text.Count)
} finally { $zip.Dispose() }

# ---- merge into the map, preserving its formatting (1-space indent, as committed)
$raw = Get-Content -LiteralPath $MapPath -Raw -Encoding UTF8
$map = $raw | ConvertFrom-Json
$added = 0; $changed = 0; $missing = @()
foreach ($m in $map) {
    if (-not $text.ContainsKey($m.id)) { $missing += $m.id; continue }
    $t = $text[$m.id]
    foreach ($p in 'why', 'target') {
        $new = $t[$p]
        $cur = if ($m.PSObject.Properties.Name -contains $p) { "$($m.$p)" } else { $null }
        if ($null -eq $cur) { $m | Add-Member -NotePropertyName $p -NotePropertyValue $new -Force; $added++ }
        elseif ($cur -ne $new) { $m.$p = $new; $changed++ }
    }
}
if ($missing.Count) { Write-Warning ("{0} control(s) in the map have no row in the workbook: {1}" -f $missing.Count, ($missing -join ', ')) }
$out = $map | ConvertTo-Json -Depth 6
# ConvertTo-Json indents with 2 spaces under PS7 and 4 under Windows PowerShell 5.1; the committed map
# uses 1 per level. Re-indent to 1 per level so the diff shows content changes, not a whole-file reformat.
# The indent unit is the smallest non-zero leading run in the output, whichever host produced it.
$lines = $out -split "`r?`n"
$unit = ($lines | ForEach-Object { $m2 = [regex]::Match($_, '^( +)'); if ($m2.Success) { $m2.Groups[1].Value.Length } } |
        Measure-Object -Minimum).Minimum
if (-not $unit -or $unit -lt 1) { $unit = 2 }
$norm = foreach ($l in $lines) {
    $m2 = [regex]::Match($l, '^( +)')
    if ($m2.Success) { (' ' * [math]::Max(1, [int]($m2.Groups[1].Value.Length / $unit))) + $l.TrimStart() } else { $l }
}
$final = ($norm -join "`n")
if ($raw.EndsWith("`n")) { $final += "`n" }
if ($PSCmdlet.ShouldProcess($MapPath, 'write why/target')) {
    Set-Content -LiteralPath $MapPath -Value $final -Encoding UTF8 -NoNewline
    Write-Host ("mapping/controls-map.json updated: {0} field(s) added, {1} changed." -f $added, $changed) -ForegroundColor Green
} else {
    Write-Host ("WhatIf: would add {0} and change {1} field(s)." -f $added, $changed) -ForegroundColor Yellow
}
