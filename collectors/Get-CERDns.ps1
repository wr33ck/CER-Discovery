#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: public DNS posture per domain - MX/gateway, SPF (lookup count, all-mechanism), DKIM selectors,
  DMARC, MTA-STS/TLS-RPT, CAA, DNSSEC, NS provider, autodiscover. No credentials needed. Feeds M365-02, M365-05, NET-10.
  Domains come from -Domains, or from the Entra/Exchange raw files of the same run (verified + authoritative custom domains).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string[]]$Domains,
    [string]$Resolver,
    [string[]]$ExtraDkimSelectors = @('selector1', 'selector2', 'google', 'k1', 'k2', 'k3', 'mimecast20230622', 'dkim', 'default', 's1', 's2', 'mail', 'zendesk1', 'hs1', 'hs2', 'mandrill', 'pm', 'sendgrid', 'smtp', 'everlytickey1', 'everlytickey2', 'mxvault')
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'DNS' -RunId $RunId
$C = 'DNS'

# --- resolver abstraction (Resolve-DnsName on Windows, dig elsewhere)
$useDig = -not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
function Resolve-CER { param([string]$Name, [string]$Type = 'A', [string]$Server)
    if (-not $Server) { $Server = $Resolver }
    try {
        if (-not $useDig) {
            $p = @{ Name = $Name; Type = $(if ($Type -eq 'TXTRAW') { 'TXT' } else { $Type }); ErrorAction = 'Stop'; DnsOnly = $true }; if ($Server) { $p['Server'] = $Server }
            $r = Resolve-DnsName @p
            switch ($Type) {
                'TXT' { return @($r | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { ($_.Strings -join '') }) }
                'TXTRAW' { return @($r | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { , @($_.Strings) }) }
                'MX' { return @($r | Where-Object { $_.Type -eq 'MX' } | Sort-Object Preference | ForEach-Object { "{0} {1}" -f $_.Preference, $_.NameExchange }) }
                'CNAME' { return @($r | Where-Object { $_.Type -eq 'CNAME' } | ForEach-Object { $_.NameHost }) }
                'NS' { return @($r | Where-Object { $_.Type -eq 'NS' } | ForEach-Object { $_.NameHost }) }
                'CAA' { return @($r | Where-Object { $_.Type -eq 'CAA' -or $_.QueryType -eq 'CAA' } | ForEach-Object { if ($_.PSObject.Properties['Data']) { $_.Data } else { "$($_.Flags) $($_.Tag) $($_.Value)" } }) }
                'DNSKEY' { return @($r | Where-Object { $_.Type -eq 'DNSKEY' } | ForEach-Object { 'DNSKEY' }) }
                default { return @($r | Where-Object { $_.Type -eq $Type } | ForEach-Object { if ($_.IPAddress) { $_.IPAddress } else { $_.NameHost } }) }
            }
        } else {
            $args2 = @('+short', '+time=4', '+tries=1'); if ($Server) { $args2 += "@$Server" }
            $qt = if ($Type -eq 'TXTRAW') { 'TXT' } else { $Type }
            $out = & dig @args2 $qt $Name 2>$null
            $lines = @($out | Where-Object { $_ -and $_ -notmatch '^;;' })
            if ($lines.Count -eq 0) { $out = & dig @args2 '+tcp' $qt $Name 2>$null; $lines = @($out | Where-Object { $_ -and $_ -notmatch '^;;' }) }
            if ($Type -eq 'TXTRAW') { return @($lines | ForEach-Object { , @(($_ -split '"\s+"') | ForEach-Object { $_ -replace '^"|"$', '' }) }) }
            if ($Type -eq 'TXT') { return @($lines | ForEach-Object { ($_ -replace '"\s+"', '') -replace '^"|"$', '' }) }
            if ($Type -eq 'CAA') { return @($lines) }
            if ($Type -eq 'DNSKEY') { return @($lines | ForEach-Object { 'DNSKEY' }) }
            return @($lines | ForEach-Object { $_.TrimEnd('.') })
        }
    } catch { return @() }
}
function Get-SpfLookups { param([string]$Domain, [int]$Depth = 0, [hashtable]$Seen, [string]$Server)
    if ($Depth -gt 6) { return 10 }
    $txt = @(Resolve-CER $Domain 'TXT' -Server $Server | Where-Object { $_ -match '^v=spf1' })
    if ($txt.Count -eq 0) { return 0 }
    $count = 0
    foreach ($tok in ($txt[0] -split '\s+')) {
        if ($tok -match '^(\+|-|~|\?)?(include:|a(:|/|$)|mx(:|/|$)|ptr(:|$)|exists:)' -or $tok -match '^redirect=') {
            $count++
            if ($tok -match '^(\+|-|~|\?)?include:(.+)$') { $inc = $Matches[2]; if (-not $Seen.ContainsKey($inc)) { $Seen[$inc] = 1; $count += (Get-SpfLookups -Domain $inc -Depth ($Depth + 1) -Seen $Seen -Server $Server) } }
            elseif ($tok -match '^redirect=(.+)$') { $inc = $Matches[1]; if (-not $Seen.ContainsKey($inc)) { $Seen[$inc] = 1; $count += (Get-SpfLookups -Domain $inc -Depth ($Depth + 1) -Seen $Seen -Server $Server) } }
        }
    }
    return $count
}

# --- domain list
$list = @()
if ($Domains) { $list = @($Domains | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ }) }
else {
    $org = Get-CERRaw -Collector 'entra' -Name 'organization'
    if ($org -and $org.Domains) { $list += @($org.Domains | Where-Object { $_.isVerified -and $_.id -notlike '*.onmicrosoft.com' } | ForEach-Object { $_.id }) }
    $oc = Get-CERRaw -Collector 'exchange' -Name 'orgconfig'
    if ($oc -and $oc.AcceptedDomains) { $list += @($oc.AcceptedDomains | Where-Object { $_.DomainName -notlike '*.onmicrosoft.com' } | ForEach-Object { $_.DomainName }) }
}
$list = @($list | ForEach-Object { $_.ToLower() } | Select-Object -Unique)
if ($list.Count -eq 0) { Set-CERCoverage -Collector $C -Section 'Domains' -Status Skipped -Note 'No domains given and none found in raw Entra/Exchange output'; Complete-CERCollector; return }
$dkimCfg = @(); $mf = Get-CERRaw -Collector 'exchange' -Name 'mailflow'; if ($mf -and $mf.Dkim) { $dkimCfg = @($mf.Dkim) }

$results = @()
Invoke-CERSection -Collector $C -Section 'Lookups' -Script {
    foreach ($d in $list) {
        Write-CERLog ("DNS {0}" -f $d)
        $mx = @(Resolve-CER $d 'MX')
        $gateway = if ($mx -match 'mimecast') { 'Mimecast' } elseif ($mx -match 'mail\.protection\.outlook\.com') { 'Exchange Online Protection' } elseif ($mx -match 'pphosted|proofpoint') { 'Proofpoint' } elseif ($mx -match 'google|googlemail') { 'Google' } elseif ($mx -match 'barracuda') { 'Barracuda' } elseif ($mx -match 'mailguard') { 'MailGuard' } elseif ($mx -match 'trendmicro') { 'Trend Micro' } elseif ($mx.Count -eq 0) { 'none (non-mail domain?)' } else { 'other/on-prem: ' + (($mx | Select-Object -First 1) -replace '^\d+\s+', '') }
        $txt = @(Resolve-CER $d 'TXT')
        $ns0 = @(Resolve-CER $d 'NS')
        $txtFailed = ($txt.Count -eq 0 -and $mx.Count -gt 0 -and $ns0.Count -gt 0 -and -not (Resolve-CER $d 'TXT'))
        $spf = @($txt | Where-Object { $_ -match '^v=spf1' })
        $spfMalformed = $false; $spfServer = $null
        if ($spf.Count -eq 0) {
            $raw = @(Resolve-CER $d 'TXTRAW')
            foreach ($rec in $raw) { $segs = @($rec); if ($segs.Count -gt 1 -and ($segs | Where-Object { $_ -match '^v=spf1' })) { $spf = @(@($segs | Where-Object { $_ -match '^v=spf1' })[0]); $spfMalformed = $true } }
        }
        if ($spfMalformed -and -not $Resolver) {
            # a mangling local resolver can merge separate TXT records into one; confirm with public resolvers before calling it malformed
            foreach ($alt in '1.1.1.1', '8.8.8.8') {
                $clean = @(Resolve-CER $d 'TXT' -Server $alt | Where-Object { $_ -match '^v=spf1' })
                if ($clean.Count -gt 0) { $spf = $clean; $spfMalformed = $false; $spfServer = $alt; break }
            }
        }
        $spfAll = if ($txtFailed) { 'lookup failed' } elseif ($spf.Count) { if ($spf[0] -match '(\+|-|~|\?)all') { $Matches[0] } else { 'no all' } } else { 'none' }
        $spfLookups = if ($spf.Count -and -not $spfMalformed) { Get-SpfLookups -Domain $d -Seen @{} -Server $spfServer } elseif ($spf.Count) { @(($spf[0] -split '\s+') | Where-Object { $_ -match '^(\+|-|~|\?)?(include:|a(:|/|$)|mx(:|/|$)|ptr(:|$)|exists:)' -or $_ -match '^redirect=' }).Count } else { 0 }
        $dmarcTxt = @(Resolve-CER "_dmarc.$d" 'TXT' | Where-Object { $_ -match '^v=DMARC1' })
        $dmarcP = if ($dmarcTxt.Count -and $dmarcTxt[0] -match 'p=(\w+)') { $Matches[1] } else { 'none/absent' }
        $dmarcSp = if ($dmarcTxt.Count -and $dmarcTxt[0] -match 'sp=(\w+)') { $Matches[1] } else { '' }
        $dmarcPct = if ($dmarcTxt.Count -and $dmarcTxt[0] -match 'pct=(\d+)') { [int]$Matches[1] } else { 100 }
        $dmarcRua = ($dmarcTxt.Count -and $dmarcTxt[0] -match 'rua=')
        $selectors = @($ExtraDkimSelectors)
        $cfg = $dkimCfg | Where-Object { $_.Domain -eq $d } | Select-Object -First 1
        $dkimFound = @()
        foreach ($s in ($selectors | Select-Object -Unique)) {
            $c = @(Resolve-CER "$s._domainkey.$d" 'CNAME'); $t = @()
            if ($c.Count -eq 0) { $t = @(Resolve-CER "$s._domainkey.$d" 'TXT' | Where-Object { $_ -match 'v=DKIM1|p=' }) }
            if ($c.Count -or $t.Count) { $dkimFound += $s }
        }
        $m365Dkim = ($dkimFound -contains 'selector1' -or $dkimFound -contains 'selector2')
        $mta = @(Resolve-CER "_mta-sts.$d" 'TXT' | Where-Object { $_ -match 'v=STSv1' }); $tlsrpt = @(Resolve-CER "_smtp._tls.$d" 'TXT' | Where-Object { $_ -match 'v=TLSRPTv1' })
        $caa = @(Resolve-CER $d 'CAA'); $dnskey = @(Resolve-CER $d 'DNSKEY'); $ns = @(Resolve-CER $d 'NS')
        $nsProvider = if ($ns -match 'easydns') { 'EasyDNS' } elseif ($ns -match 'cloudflare') { 'Cloudflare' } elseif ($ns -match 'azure-dns') { 'Azure DNS' } elseif ($ns -match 'awsdns') { 'Route 53' } elseif ($ns -match 'domaincontrol') { 'GoDaddy' } elseif ($ns -match 'crazydomains|ventraip|netregistry|synergywholesale|tppwholesale|partnerconsole') { 'AU registrar DNS' } elseif ($ns.Count) { ($ns | Select-Object -First 1) } else { 'n/a' }
        $auto = @(Resolve-CER "autodiscover.$d" 'CNAME'); $autoA = if ($auto.Count -eq 0) { @(Resolve-CER "autodiscover.$d" 'A') } else { @() }
        $autoTarget = if ($auto.Count) { $auto[0] } elseif ($autoA.Count) { $autoA[0] } else { '' }
        $script:results += [pscustomobject]@{
            Domain = $d; MX = ($mx -join '; '); Gateway = $gateway; SPF = $(if ($spf.Count) { $spf[0] } else { '' }); SPFRecords = $spf.Count; SPFAll = $spfAll; SPFLookups = $spfLookups; SPFMalformed = $spfMalformed; TxtLookupFailed = $txtFailed
            DMARC = $(if ($dmarcTxt.Count) { $dmarcTxt[0] } else { '' }); DMARCPolicy = $dmarcP; DMARCSubPolicy = $dmarcSp; DMARCPct = $dmarcPct; DMARCReporting = $dmarcRua
            DKIMSelectorsFound = ($dkimFound -join ','); M365DKIMinDNS = $m365Dkim; M365DKIMEnabled = $(if ($cfg) { $cfg.Enabled } else { $null }); MTASTS = ($mta.Count -gt 0); TLSRPT = ($tlsrpt.Count -gt 0)
            CAA = ($caa -join '; '); DNSSEC = ($dnskey.Count -gt 0); NS = ($ns -join '; '); NSProvider = $nsProvider; Autodiscover = $autoTarget
        }
    }
    Save-CERRaw -Name 'domains' -Object $results
    $mail = @($results | Where-Object { $_.MX -and $_.Gateway -notlike 'none*' })
    $bad = @($mail | Where-Object { -not $_.TxtLookupFailed -and ($_.SPFRecords -ne 1 -or $_.SPFMalformed -or $_.SPFAll -notin '-all', '~all' -or $_.SPFLookups -gt 10 -or $_.DMARCPolicy -notin 'quarantine', 'reject' -or -not $_.DMARCReporting -or $_.DKIMSelectorsFound -eq '') })
    $failedLookups = @($results | Where-Object TxtLookupFailed)
    $parkedBad = @($results | Where-Object { $_.Gateway -like 'none*' -and ($_.SPF -ne 'v=spf1 -all' -or $_.DMARCPolicy -ne 'reject') })
    Add-CEREvidence -Control 'M365-02' -Flag $(if ($bad.Count) { 'Attention' } else { 'OK' }) -Evidence ("DNS for {0} domains ({1} mail-enabled). Fully aligned (single SPF with -all/~all and <= 10 lookups, DKIM selector live, DMARC quarantine/reject with rua): {2}/{3}. Needs work: {4}. Parked/non-mail domains without null SPF + DMARC reject: {5} ({6}). Gateways: {7}.{8}" -f $results.Count, $mail.Count, ($mail.Count - $bad.Count - $failedLookups.Count), $mail.Count, (Join-CERList ($bad | ForEach-Object { "{0} [SPF {1} x{2}{7}, {3} lookups; DKIM {4}; DMARC p={5} rua={6}]" -f $_.Domain, $_.SPFAll, $_.SPFRecords, $_.SPFLookups, $(if ($_.DKIMSelectorsFound) { $_.DKIMSelectorsFound } else { 'none found' }), $_.DMARCPolicy, $_.DMARCReporting, $(if ($_.SPFMalformed) { ' MALFORMED: v=spf1 is not the first/only string in its TXT record (RFC 7208 concatenation breaks it)' } else { '' }) }) 6), $parkedBad.Count, (Join-CERList ($parkedBad | ForEach-Object { $_.Domain }) 5), (Join-CERList ($mail | Group-Object Gateway | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 4), $(if ($failedLookups.Count) { " TXT lookup failed (resolver/TCP issue) for: " + (($failedLookups | ForEach-Object { $_.Domain }) -join ', ') + " - re-run from another network." } else { '' }))
    $noCaa = @($results | Where-Object { -not $_.CAA }); $dnssec = @($results | Where-Object DNSSEC)
    Add-CEREvidence -Control 'NET-10' -Flag $(if ($noCaa.Count -eq $results.Count) { 'Attention' } else { 'Info' }) -Evidence ("Domain hygiene: NS providers {0}; CAA record present on {1}/{2}; DNSSEC signed {3}/{2}; MTA-STS {4}, TLS-RPT {5}. Registrar lock and expiry dates: check TPP Wholesale / whois (manual)." -f (Join-CERList ($results | Group-Object NSProvider | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 4), ($results.Count - $noCaa.Count), $results.Count, $dnssec.Count, @($results | Where-Object MTASTS).Count, @($results | Where-Object TLSRPT).Count)
    $onprem = @($results | Where-Object { $_.Autodiscover -and $_.Autodiscover -notmatch 'autodiscover\.outlook\.com|outlook\.office365\.com|mail\.protection' })
    $mxOnprem = @($mail | Where-Object { $_.Gateway -like 'other/on-prem*' })
    if ($onprem.Count -or $mxOnprem.Count) { Add-CEREvidence -Control 'M365-05' -Flag Attention -Evidence ("Autodiscover/MX pointing at non-Microsoft/non-gateway hosts (possible on-prem Exchange still published): {0}" -f (Join-CERList (($onprem | ForEach-Object { "{0} -> {1}" -f $_.Domain, $_.Autodiscover }) + ($mxOnprem | ForEach-Object { "{0} MX {1}" -f $_.Domain, $_.MX })) 5)) }
}
Complete-CERCollector
