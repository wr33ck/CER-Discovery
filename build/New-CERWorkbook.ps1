#Requires -Version 5.1
<#
.SYNOPSIS
  Builds a standalone Excel workbook from one run's evidence.csv - one tab per review domain, plus
  Summary and Attention tabs.

.DESCRIPTION
  No Excel, no ImportExcel module: writes the .xlsx directly as a zip of OOXML parts, the same
  no-dependency approach Sync-CERControlText.ps1 uses to READ a workbook, so it runs on the bA laptop
  and on a jump host with nothing to install.

  Reads evidence.csv (and pack.json, if present, for the collector roll-up) from a run folder already
  built by New-CEREvidencePack.ps1 - it re-shapes evidence that already exists, it does not re-derive it.
  Run New-CEREvidencePack.ps1 (or Invoke-CERDiscovery.ps1, which calls it) first if evidence.csv is
  missing.

  Output: <run folder>\Client-Environment-Review-<Client>-<RunId>.xlsx
    Summary    - run metadata, controls by status, controls by domain, evidence by collector
    Attention  - every control with at least one Attention finding, across all domains, in one list
    <domain>   - one tab per review domain (tab name = the domain's short code, e.g. IAM, M365, SRV -
                 controls-map.json's `dom` field), every control in that domain with its evidence, why
                 it matters, target state and recommended action - the sheet equivalent of
                 summary.html's "All controls by domain" section

  Row fill colour follows the worst Flag on the control (Attention/OK/Info/Unknown), the same colours
  summary.html uses for its chips, so a coloured scan works the same way in Excel as in the HTML report.

.EXAMPLE
  .\New-CERWorkbook.ps1 -Client C-003              # latest run for the client
  .\New-CERWorkbook.ps1 -RunDir D:\CER\output\C-003\20260905-0900
#>
[CmdletBinding()]
param([string]$Client, [string]$OutputRoot, [string]$RunId, [string]$RunDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $RunDir) {
    if (-not $Client) { throw 'Give -RunDir or -Client (+ -OutputRoot / -RunId)' }
    if (-not $OutputRoot) { $OutputRoot = Join-Path (Get-Location).Path 'output' }
    $clientDir = Join-Path $OutputRoot $Client
    if ($RunId) { $RunDir = Join-Path $clientDir $RunId } else { $RunDir = (Get-ChildItem -LiteralPath $clientDir -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName }
}
if (-not (Test-Path -LiteralPath $RunDir)) { throw "Run folder not found: $RunDir" }
$RunDir = (Resolve-Path -LiteralPath $RunDir).ProviderPath
$RunId = Split-Path $RunDir -Leaf; $Client = Split-Path (Split-Path $RunDir -Parent) -Leaf
$evidenceCsv = Join-Path $RunDir 'evidence.csv'
if (-not (Test-Path -LiteralPath $evidenceCsv)) { throw "evidence.csv not found in $RunDir - run New-CEREvidencePack.ps1 (or Invoke-CERDiscovery.ps1) first, then re-run this." }
$rows = @(Import-Csv -LiteralPath $evidenceCsv -Encoding UTF8)
if (-not $rows.Count) { throw "evidence.csv in $RunDir has no rows." }

$pack = $null
$packPath = Join-Path $RunDir 'pack.json'
if (Test-Path -LiteralPath $packPath) { try { $pack = Get-Content -LiteralPath $packPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }

$map = @()
$mapPath = Join-Path $root 'mapping/controls-map.json'
if (Test-Path -LiteralPath $mapPath) { try { $map = @(Get-Content -LiteralPath $mapPath -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }

# Domain order + short code (workbook tab name): first-appearance order in controls-map.json, so tabs
# read left-to-right in the same order as the review's 11 domains. Falls back to CSV row order, and to a
# code derived from the domain name, if the map is not sitting next to this script.
$domainOrder = New-Object System.Collections.Generic.List[string]
$domainCode = @{}
foreach ($m in $map) {
    if (-not $domainOrder.Contains($m.domain)) { $domainOrder.Add($m.domain) }
    if ($m.domain -and -not $domainCode.ContainsKey($m.domain)) { $domainCode[$m.domain] = $m.dom }
}
foreach ($r in $rows) { if ($r.Domain -and -not $domainOrder.Contains($r.Domain)) { $domainOrder.Add($r.Domain) } }

# ============================================================================================
#  Minimal, dependency-free .xlsx writer - a zip of OOXML parts. No ImportExcel, no Excel COM.
# ============================================================================================
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function _xesc {
    <# XML-escape cell text; drop characters XML 1.0 cannot carry at all (control chars other than tab/LF/CR). #>
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = "$Text" -replace "`r`n", "`n"
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $t.ToCharArray()) {
        $code = [int][char]$ch
        if ($code -eq 9 -or $code -eq 10 -or $code -eq 13 -or ($code -ge 32 -and $code -ne 127)) { $null = $sb.Append($ch) }
    }
    $t = $sb.ToString()
    $t = $t.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    return $t
}
function _colLetter {
    param([int]$Index)   # 1-based
    $s = ''; $n = $Index
    while ($n -gt 0) { $rem = ($n - 1) % 26; $s = [char](65 + $rem) + $s; $n = [int](($n - 1) / 26) }
    return $s
}
function _safeSheetName {
    param([string]$Name, [System.Collections.Generic.HashSet[string]]$Used)
    $n = ($Name -replace '[:\\/\?\*\[\]]', ' ').Trim()
    if ($n.Length -gt 31) { $n = $n.Substring(0, 31).Trim() }
    if (-not $n) { $n = 'Sheet' }
    $base = $n; $i = 2
    while ($Used.Contains($n)) { $suffix = " ($i)"; $keep = [Math]::Max(1, 31 - $suffix.Length); $n = $base.Substring(0, [Math]::Min($base.Length, $keep)) + $suffix; $i++ }
    $null = $Used.Add($n)
    return $n
}
function _rowXml {
    <# One <row>: $Cells in order from column A, all sharing $Style. A blank cell is written without
       a value (still styled, so a fill colour carries across the whole row even where a column is empty). #>
    param([int]$RowNum, [string[]]$Cells, [int]$Style)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<row r="' + $RowNum + '">')
    for ($i = 0; $i -lt $Cells.Count; $i++) {
        $ref = (_colLetter ($i + 1)) + $RowNum
        $v = "$($Cells[$i])"
        if ($v -eq '') { $null = $sb.Append('<c r="' + $ref + '" s="' + $Style + '"/>') }
        else { $null = $sb.Append('<c r="' + $ref + '" t="inlineStr" s="' + $Style + '"><is><t xml:space="preserve">' + (_xesc $v) + '</t></is></c>') }
    }
    $null = $sb.Append('</row>')
    return $sb.ToString()
}
function New-CERWorksheetXml {
    <# Assembles one worksheet part from a flat list of row-defs (@{Cells=;Style=}), in the schema
       order Excel requires: sheetViews, cols, sheetData, autoFilter, mergeCells. #>
    param(
        [int[]]$ColWidths,
        [System.Collections.Generic.List[object]]$RowDefs,
        [int]$AutoFilterRow = 0,
        [int]$AutoFilterCols = 0,
        [int]$FreezeAfterRow = 0,
        [string[]]$MergeRanges = @()
    )
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    $null = $sb.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">')
    if ($FreezeAfterRow -gt 0) {
        $null = $sb.Append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="' + $FreezeAfterRow + '" topLeftCell="A' + ($FreezeAfterRow + 1) + '" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft"/></sheetView></sheetViews>')
    } else {
        $null = $sb.Append('<sheetViews><sheetView workbookViewId="0"/></sheetViews>')
    }
    if ($ColWidths -and $ColWidths.Count) {
        $null = $sb.Append('<cols>')
        for ($i = 0; $i -lt $ColWidths.Count; $i++) { $null = $sb.Append('<col min="' + ($i + 1) + '" max="' + ($i + 1) + '" width="' + $ColWidths[$i] + '" customWidth="1"/>') }
        $null = $sb.Append('</cols>')
    }
    $null = $sb.Append('<sheetData>')
    $r = 0
    foreach ($def in $RowDefs) { $r++; $null = $sb.Append((_rowXml -RowNum $r -Cells $def.Cells -Style $def.Style)) }
    $null = $sb.Append('</sheetData>')
    if ($AutoFilterRow -gt 0 -and $AutoFilterCols -gt 0) {
        $lastCol = _colLetter $AutoFilterCols
        $null = $sb.Append('<autoFilter ref="A' + $AutoFilterRow + ':' + $lastCol + $AutoFilterRow + '"/>')
    }
    if ($MergeRanges.Count) {
        $null = $sb.Append('<mergeCells count="' + $MergeRanges.Count + '">')
        foreach ($mr in $MergeRanges) { $null = $sb.Append('<mergeCell ref="' + $mr + '"/>') }
        $null = $sb.Append('</mergeCells>')
    }
    $null = $sb.Append('</worksheet>')
    return $sb.ToString()
}

$CERStylesXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="3">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="14"/><color rgb="FF1F3864"/><name val="Calibri"/></font>
</fonts>
<fills count="7">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFF2F4F7"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFEF3F2"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFECFDF3"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFEFF8FF"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFEDEFF2"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="9">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
<xf numFmtId="0" fontId="0" fillId="6" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>
'@

function Write-CERXlsx {
    param([string]$Path, [System.Collections.Generic.List[object]]$Sheets, [string]$StylesXml)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            function _writeEntry {
                param($Zip, $Name, $Content)
                $entry = $Zip.CreateEntry($Name, [System.IO.Compression.CompressionLevel]::Optimal)
                $es = $entry.Open()
                try { $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content); $es.Write($bytes, 0, $bytes.Length) } finally { $es.Dispose() }
            }
            $n = $Sheets.Count

            $ct = New-Object System.Text.StringBuilder
            $null = $ct.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>')
            for ($i = 1; $i -le $n; $i++) { $null = $ct.Append('<Override PartName="/xl/worksheets/sheet' + $i + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>') }
            $null = $ct.Append('<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')
            _writeEntry $zip '[Content_Types].xml' $ct.ToString()

            $rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>'
            _writeEntry $zip '_rels/.rels' $rootRels

            $created = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $core = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Client Environment Review evidence</dc:title><dc:creator>CER-Discovery</dc:creator><cp:lastModifiedBy>CER-Discovery</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">' + $created + '</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">' + $created + '</dcterms:modified></cp:coreProperties>'
            _writeEntry $zip 'docProps/core.xml' $core

            $titles = ($Sheets | ForEach-Object { '<vt:lpstr>' + (_xesc $_.Name) + '</vt:lpstr>' }) -join ''
            $app = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>CER-Discovery</Application><DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop><HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant><vt:variant><vt:i4>' + $n + '</vt:i4></vt:variant></vt:vector></HeadingPairs><TitlesOfParts><vt:vector size="' + $n + '" baseType="lpstr">' + $titles + '</vt:vector></TitlesOfParts><LinksUpToDate>false</LinksUpToDate><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>16.0000</AppVersion></Properties>'
            _writeEntry $zip 'docProps/app.xml' $app

            $wbSheets = New-Object System.Text.StringBuilder
            $wbRels = New-Object System.Text.StringBuilder
            $null = $wbRels.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">')
            for ($i = 1; $i -le $n; $i++) {
                $s = $Sheets[$i - 1]
                $null = $wbSheets.Append('<sheet name="' + (_xesc $s.Name) + '" sheetId="' + $i + '" r:id="rId' + $i + '"/>')
                $null = $wbRels.Append('<Relationship Id="rId' + $i + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + $i + '.xml"/>')
                _writeEntry $zip ('xl/worksheets/sheet' + $i + '.xml') $s.Xml
            }
            $stylesRid = $n + 1
            $null = $wbRels.Append('<Relationship Id="rId' + $stylesRid + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>')
            $null = $wbRels.Append('</Relationships>')
            _writeEntry $zip 'xl/_rels/workbook.xml.rels' $wbRels.ToString()

            $workbookXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView activeTab="0"/></bookViews><sheets>' + $wbSheets.ToString() + '</sheets></workbook>'
            _writeEntry $zip 'xl/workbook.xml' $workbookXml

            _writeEntry $zip 'xl/styles.xml' $StylesXml
        } finally { $zip.Dispose() }
    } finally { $fs.Dispose() }
}

# ============================================================================================
#  Build the sheets
# ============================================================================================
$S_DEFAULT = 0; $S_HEADER = 1; $S_TITLE = 2; $S_BODY = 3; $S_ATTN = 4; $S_OK = 5; $S_INFO = 6; $S_UNK = 7; $S_LABEL = 8
function _flagStyle { param([string]$Flag)
    if ($Flag -eq 'Attention') { return $S_ATTN }
    if ($Flag -eq 'OK') { return $S_OK }
    if ($Flag -eq 'Info') { return $S_INFO }
    if ($Flag -eq 'Unknown') { return $S_UNK }
    return $S_BODY
}
function _statusCounts { param($Set)
    [ordered]@{
        Collected     = @($Set | Where-Object { $_.Status -eq 'Collected' }).Count
        Partial       = @($Set | Where-Object { $_.Status -eq 'Partial' }).Count
        'Not collected' = @($Set | Where-Object { $_.Status -eq 'Not collected' }).Count
        'Not run'     = @($Set | Where-Object { $_.Status -eq 'Not run' }).Count
        Manual        = @($Set | Where-Object { $_.Status -eq 'Manual' }).Count
        Attention     = @($Set | Where-Object { $_.Flag -eq 'Attention' }).Count
    }
}
$usedNames = New-Object System.Collections.Generic.HashSet[string]
$sheets = New-Object System.Collections.Generic.List[object]

# ---------------- Summary ----------------
$ran = if ($pack -and $pack.Collectors) { @($pack.Collectors) } else { @($rows | ForEach-Object { $_.Collectors -split ',' } | Where-Object { $_ } | Select-Object -Unique | Sort-Object) }
$generated = if ($pack -and $pack.Generated) { "$($pack.Generated)" } else { (Get-Date).ToString('s') }
$overall = _statusCounts $rows
$sumDefs = New-Object System.Collections.Generic.List[object]
$sumDefs.Add(@{ Cells = @('Client Environment Review - discovery evidence'); Style = $S_TITLE })
$sumDefs.Add(@{ Cells = @(("Client: {0}    Run: {1}    Generated: {2}" -f $Client, $RunId, $generated)); Style = $S_DEFAULT })
$sumDefs.Add(@{ Cells = @(("Collectors: {0}" -f ($ran -join ', '))); Style = $S_DEFAULT })
$sumDefs.Add(@{ Cells = @('Internal working output - contains real names and hostnames. Keep local; sanitise before it leaves. The tool reports what it saw, the score is the reviewer''s.'); Style = $S_DEFAULT })
$sumDefs.Add(@{ Cells = @(''); Style = $S_DEFAULT })
$sumDefs.Add(@{ Cells = @('Controls by status'); Style = $S_LABEL })
$sumDefs.Add(@{ Cells = @('Status', 'Count'); Style = $S_HEADER })
foreach ($k in 'Collected', 'Partial', 'Not collected', 'Not run', 'Manual') { $sumDefs.Add(@{ Cells = @($k, "$($overall[$k])"); Style = $S_BODY }) }
$sumDefs.Add(@{ Cells = @('Attention findings', "$($overall['Attention'])"); Style = $S_ATTN })
$sumDefs.Add(@{ Cells = @(''); Style = $S_DEFAULT })
$sumDefs.Add(@{ Cells = @('Controls by domain'); Style = $S_LABEL })
$sumDefs.Add(@{ Cells = @('Domain', 'Controls', 'Collected', 'Partial', 'Not collected', 'Not run', 'Manual', 'Attention'); Style = $S_HEADER })
foreach ($d in $domainOrder) {
    $dRows = @($rows | Where-Object { $_.Domain -eq $d })
    if (-not $dRows.Count) { continue }
    $c = _statusCounts $dRows
    $sumDefs.Add(@{ Cells = @($d, "$($dRows.Count)", "$($c.Collected)", "$($c.Partial)", "$($c['Not collected'])", "$($c['Not run'])", "$($c.Manual)", "$($c.Attention)"); Style = $S_BODY })
}
if ($pack -and $pack.ByCollector -and @($pack.ByCollector).Count) {
    $sumDefs.Add(@{ Cells = @(''); Style = $S_DEFAULT })
    $sumDefs.Add(@{ Cells = @('Evidence by collector'); Style = $S_LABEL })
    $sumDefs.Add(@{ Cells = @('Collector', 'Evidence rows', 'Controls touched', 'Attention', 'Sections'); Style = $S_HEADER })
    foreach ($b in $pack.ByCollector) { $sumDefs.Add(@{ Cells = @("$($b.Collector)", "$($b.EvidenceRows)", "$($b.Controls)", "$($b.Attention)", "$($b.Sections)"); Style = $S_BODY }) }
}
$sumName = _safeSheetName 'Summary' $usedNames
$sumXml = New-CERWorksheetXml -ColWidths @(30, 16, 16, 16, 16, 16, 16, 16) -RowDefs $sumDefs -MergeRanges @('A1:H1')
$sheets.Add(@{ Name = $sumName; Xml = $sumXml })

# ---------------- Attention ----------------
$attnCols = @('ID', 'Domain', 'Control', 'Status', 'Evidence', 'Why it matters', 'Target state', 'Recommended', 'Where to find the rest', 'Collectors')
$attnWidths = @(9, 20, 44, 13, 58, 32, 32, 32, 28, 18)
$attnRows = @($rows | Where-Object { $_.Flag -eq 'Attention' } | Sort-Object Domain, ID)
$attnDefs = New-Object System.Collections.Generic.List[object]
$attnDefs.Add(@{ Cells = @(("Attention findings ({0} of {1} controls)" -f $attnRows.Count, $rows.Count)); Style = $S_TITLE })
$attnDefs.Add(@{ Cells = $attnCols; Style = $S_HEADER })
foreach ($r in $attnRows) {
    $attnDefs.Add(@{ Cells = @("$($r.ID)", "$($r.Domain)", "$($r.Control)", "$($r.Status)", "$($r.Evidence)", "$($r.WhyItMatters)", "$($r.TargetState)", "$($r.RecommendedActions)", "$($r.ManualSource)", "$($r.Collectors)"); Style = $S_BODY })
}
$attnName = _safeSheetName 'Attention' $usedNames
$attnXml = New-CERWorksheetXml -ColWidths $attnWidths -RowDefs $attnDefs -AutoFilterRow 2 -AutoFilterCols $attnCols.Count -FreezeAfterRow 2 -MergeRanges @(('A1:' + (_colLetter $attnCols.Count) + '1'))
$sheets.Add(@{ Name = $attnName; Xml = $attnXml })

# ---------------- one sheet per domain ----------------
$domainCols = @('ID', 'Control', 'Status', 'Flag', 'Evidence', 'Why it matters', 'Target state', 'Recommended', 'Where to find the rest', 'Note', 'Collectors')
$domainWidths = @(9, 44, 13, 11, 58, 32, 32, 32, 28, 22, 18)
foreach ($d in $domainOrder) {
    $dRows = @($rows | Where-Object { $_.Domain -eq $d } | Sort-Object ID)
    if (-not $dRows.Count) { continue }
    $code = $d
    if ($domainCode.ContainsKey($d) -and $domainCode[$d]) { $code = $domainCode[$d] }
    $defs = New-Object System.Collections.Generic.List[object]
    $defs.Add(@{ Cells = @(("{0} - {1} ({2} controls)" -f $code, $d, $dRows.Count)); Style = $S_TITLE })
    $defs.Add(@{ Cells = $domainCols; Style = $S_HEADER })
    foreach ($r in $dRows) {
        $style = _flagStyle $r.Flag
        $defs.Add(@{ Cells = @("$($r.ID)", "$($r.Control)", "$($r.Status)", "$($r.Flag)", "$($r.Evidence)", "$($r.WhyItMatters)", "$($r.TargetState)", "$($r.RecommendedActions)", "$($r.ManualSource)", "$($r.Note)", "$($r.Collectors)"); Style = $style })
    }
    $name = _safeSheetName $code $usedNames
    $xml = New-CERWorksheetXml -ColWidths $domainWidths -RowDefs $defs -AutoFilterRow 2 -AutoFilterCols $domainCols.Count -FreezeAfterRow 2 -MergeRanges @(('A1:' + (_colLetter $domainCols.Count) + '1'))
    $sheets.Add(@{ Name = $name; Xml = $xml })
}

$outPath = Join-Path $RunDir ("Client-Environment-Review-{0}-{1}.xlsx" -f $Client, $RunId)
Write-CERXlsx -Path $outPath -Sheets $sheets -StylesXml $CERStylesXml
Write-Host ("Workbook written: {0}  ({1} sheets: Summary, Attention, {2} domains)" -f $outPath, $sheets.Count, ($sheets.Count - 2))
