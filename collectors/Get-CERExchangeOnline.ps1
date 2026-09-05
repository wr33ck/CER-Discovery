#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: Exchange Online + Security & Compliance (Purview) via ExchangeOnlineManagement v3.
  Feeds M365-02/03/04/05/07/08/12, IAM-04, END-14, LIC-04.
.EXAMPLE
  .\Get-CERExchangeOnline.ps1 -Client C-003 -RunId 20260905-0900 -UserPrincipalName admin.b.shrestha@blueapache.com -DelegatedOrganization contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$DelegatedOrganization,
    [switch]$SkipPurview,
    [switch]$CheckInboxRules,
    [int]$MaxMailboxStats = 1500,
    [int]$StaleDays = 90
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Exchange' -RunId $RunId
$C = 'Exchange'
if (-not (Test-CERModule -Name ExchangeOnlineManagement -Collector $C)) { Complete-CERCollector; return }
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$now = Get-Date

Invoke-CERSection -Collector $C -Section 'Connect' -Script {
    $p = @{ UserPrincipalName = $UserPrincipalName; ShowBanner = $false; ErrorAction = 'Stop' }
    if ($DelegatedOrganization) { $p['DelegatedOrganization'] = $DelegatedOrganization }
    Connect-ExchangeOnline @p
    $oc = Get-OrganizationConfig
    Write-CERLog ("Connected to EXO: {0}" -f $oc.Name)
}
$acceptedDomains = @()

Invoke-CERSection -Collector $C -Section 'OrgConfigAudit' -Script {
    $oc = Get-OrganizationConfig
    $aal = Get-AdminAuditLogConfig
    $tc = Get-TransportConfig
    $script:acceptedDomains = @(Get-AcceptedDomain | Select-Object DomainName, DomainType, Default, InitialDomain)
    $hybrid = @(); try { $hybrid = @(Get-OnPremisesOrganization -ErrorAction Stop | Select-Object Identity, HybridDomains, OrganizationName) } catch { }
    $ioc = @(); try { $ioc = @(Get-IntraOrganizationConnector -ErrorAction Stop | Select-Object Name, TargetAddressDomains, Enabled) } catch { }
    $authPol = @(Get-AuthenticationPolicy | Select-Object Name, AllowBasicAuthActiveSync, AllowBasicAuthImap, AllowBasicAuthPop, AllowBasicAuthSmtp, AllowBasicAuthOutlookService, AllowBasicAuthPowershell)
    $plans = @(Get-CASMailboxPlan | Select-Object Name, ImapEnabled, PopEnabled, ActiveSyncEnabled)
    Save-CERRaw -Name 'orgconfig' -Object ([ordered]@{ Org = ($oc | Select-Object Name, AuditDisabled, OAuth2ClientProfileEnabled, DefaultAuthenticationPolicy, SendFromAliasEnabled, MailTipsExternalRecipientsTipsEnabled, IsDehydrated, ExchangeVersion, DefaultPublicFolderMailbox, CustomerLockboxEnabled, AutoExpandingArchiveEnabled, OutlookMobileGCCRestrictionsEnabled); AuditLog = ($aal | Select-Object UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled); Transport = ($tc | Select-Object SmtpClientAuthenticationDisabled, ExternalPostmasterAddress, MaxSendSize, MaxReceiveSize); AcceptedDomains = $script:acceptedDomains; Hybrid = $hybrid; IntraOrgConnectors = $ioc; AuthenticationPolicies = $authPol; CASMailboxPlans = $plans })
    $flag = if ($oc.AuditDisabled -or -not $aal.UnifiedAuditLogIngestionEnabled -or -not $tc.SmtpClientAuthenticationDisabled) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'M365-04' -Flag $flag -Evidence ("Exchange Online org '{0}': mailbox auditing default {1} (AuditDisabled={2}); unified audit log ingestion {3}; Modern auth (OAuth2ClientProfileEnabled) {4}; org-wide SMTP AUTH disabled {5}; default authentication policy '{6}'." -f $oc.Name, $(if ($oc.AuditDisabled) { 'OFF' } else { 'on' }), $oc.AuditDisabled, $aal.UnifiedAuditLogIngestionEnabled, $oc.OAuth2ClientProfileEnabled, $tc.SmtpClientAuthenticationDisabled, $oc.DefaultAuthenticationPolicy)
    Add-CEREvidence -Control 'IAM-04' -Flag $(if ($tc.SmtpClientAuthenticationDisabled) { 'OK' } else { 'Attention' }) -Evidence ("EXO: SMTP AUTH disabled org-wide = {0}; authentication policies: {1}; CAS mailbox plans allow IMAP/POP by default: {2}." -f $tc.SmtpClientAuthenticationDisabled, (Join-CERList ($authPol | ForEach-Object { "{0} (basic ActiveSync={1}, IMAP={2}, POP={3}, SMTP={4})" -f $_.Name, $_.AllowBasicAuthActiveSync, $_.AllowBasicAuthImap, $_.AllowBasicAuthPop, $_.AllowBasicAuthSmtp }) 3), (Join-CERList ($plans | ForEach-Object { "{0}: IMAP={1} POP={2}" -f $_.Name, $_.ImapEnabled, $_.PopEnabled }) 3))
    Add-CEREvidence -Control 'M365-05' -Flag $(if ($hybrid.Count) { 'Attention' } else { 'Info' }) -Evidence ("Hybrid configuration objects in EXO (Get-OnPremisesOrganization): {0} ({1}); intra-org connectors: {2}. Hybrid present means an on-prem Exchange server still exists (or was never cleaned up)." -f $hybrid.Count, (Join-CERList ($hybrid | ForEach-Object { $_.OrganizationName }) 3), $ioc.Count)
    Add-CEREvidence -Control 'M365-02' -Flag Info -Evidence ("Accepted domains: {0} ({1} authoritative, {2} internal relay). DNS checks per domain are in the DNS collector." -f $script:acceptedDomains.Count, @($script:acceptedDomains | Where-Object { $_.DomainType -eq 'Authoritative' }).Count, @($script:acceptedDomains | Where-Object { $_.DomainType -eq 'InternalRelay' }).Count)
}

Invoke-CERSection -Collector $C -Section 'DkimForwardingRules' -Script {
    $dkim = @(Get-DkimSigningConfig | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME, LastChecked)
    $osp = @(Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode, IsDefault, RecipientLimitExternalPerHour, ActionWhenThresholdReached)
    $rd = @(Get-RemoteDomain | Select-Object DomainName, AutoForwardEnabled, AutoReplyEnabled)
    $rules = @(Get-TransportRule | Select-Object Name, State, Priority, Mode, RedirectMessageTo, BlindCopyTo, CopyTo, SetSCL, SetHeaderName, SetHeaderValue, FromScope, SentToScope, SenderDomainIs, ExceptIfSenderDomainIs, WhenChanged)
    $extForward = @($rules | Where-Object { $_.State -eq 'Enabled' -and ($_.RedirectMessageTo -or $_.BlindCopyTo -or $_.CopyTo) })
    $sclBypass = @($rules | Where-Object { $_.State -eq 'Enabled' -and $_.SetSCL -eq -1 })
    $inbound = @(Get-InboundConnector | Select-Object Name, Enabled, ConnectorType, SenderIPAddresses, SenderDomains, RestrictDomainsToIPAddresses, RestrictDomainsToCertificate, RequireTls, TlsSenderCertificateName, EFSkipLastIP, EFSkipIPs, TreatMessagesAsInternal)
    $outbound = @(Get-OutboundConnector | Select-Object Name, Enabled, ConnectorType, SmartHosts, RecipientDomains, UseMXRecord, TlsSettings, IsTransportRuleScoped)
    Save-CERRaw -Name 'mailflow' -Object ([ordered]@{ Dkim = $dkim; OutboundSpam = $osp; RemoteDomains = $rd; TransportRules = $rules; InboundConnectors = $inbound; OutboundConnectors = $outbound })
    $auth = @($script:acceptedDomains | Where-Object { $_.DomainType -eq 'Authoritative' -and -not $_.InitialDomain })
    $dkimOff = @($auth | Where-Object { $d = $_.DomainName; -not ($dkim | Where-Object { $_.Domain -eq $d -and $_.Enabled }) })
    Add-CEREvidence -Control 'M365-02' -Flag $(if ($dkimOff.Count) { 'Attention' } else { 'OK' }) -Evidence ("M365 DKIM signing enabled for {0}/{1} authoritative custom domains; not enabled: {2}. (Mimecast or other gateway DKIM is checked via DNS selectors.)" -f ($auth.Count - $dkimOff.Count), $auth.Count, (Join-CERList ($dkimOff | ForEach-Object { $_.DomainName }) 6))
    $fwdOpen = @($osp | Where-Object { $_.AutoForwardingMode -ne 'Off' }); $rdOpen = @($rd | Where-Object { $_.AutoForwardEnabled })
    Add-CEREvidence -Control 'M365-04' -Flag $(if ($fwdOpen.Count -or $extForward.Count -or $sclBypass.Count) { 'Attention' } else { 'OK' }) -Evidence ("Auto-forwarding: outbound spam policies with AutoForwardingMode <> Off: {0} ({1}); remote domains allowing auto-forward: {2} ({3}); transport rules that redirect/BCC/copy: {4} ({5}); transport rules setting SCL -1 (spam bypass): {6} ({7}); total rules {8} ({9} enabled)." -f $fwdOpen.Count, (Join-CERList ($fwdOpen | ForEach-Object { "{0}={1}" -f $_.Name, $_.AutoForwardingMode }) 3), $rdOpen.Count, (Join-CERList ($rdOpen | ForEach-Object { $_.DomainName }) 3), $extForward.Count, (Join-CERList ($extForward | ForEach-Object { $_.Name }) 4), $sclBypass.Count, (Join-CERList ($sclBypass | ForEach-Object { $_.Name }) 4), $rules.Count, @($rules | Where-Object { $_.State -eq 'Enabled' }).Count)
    $partner = @($inbound | Where-Object { $_.Enabled -and $_.ConnectorType -eq 'Partner' })
    $locked = @($partner | Where-Object { $_.RestrictDomainsToIPAddresses -or $_.RestrictDomainsToCertificate })
    $gateway = if ($outbound | Where-Object { $_.Enabled -and ($_.SmartHosts -match 'mimecast') }) { 'Mimecast (outbound smart host)' } elseif ($inbound | Where-Object { $_.SenderIPAddresses -or $_.TlsSenderCertificateName -match 'mimecast|proofpoint|barracuda|sophos|trendmicro|mailguard' }) { 'third-party gateway (inbound partner connector)' } else { 'Exchange Online Protection direct (or gateway not visible in connectors)' }
    Add-CEREvidence -Control 'M365-03' -Flag $(if ($partner.Count -and -not $locked.Count) { 'Attention' } else { 'Info' }) -Evidence ("Mail path: {0}. Inbound partner connectors: {1} ({2}), of which restricted by IP/certificate: {3}; enhanced filtering skip-list set on {4}. Outbound connectors: {5} ({6}). If a gateway is in front, an EXO transport rule/connector must reject mail not from the gateway IPs (MX bypass)." -f $gateway, $partner.Count, (Join-CERList ($partner | ForEach-Object { $_.Name }) 3), $locked.Count, @($inbound | Where-Object { $_.EFSkipIPs -or $_.EFSkipLastIP }).Count, $outbound.Count, (Join-CERList ($outbound | ForEach-Object { "{0} -> {1}" -f $_.Name, (($_.SmartHosts) -join '/') }) 3))
}

Invoke-CERSection -Collector $C -Section 'ThreatPolicies' -Script {
    $eop = @(); $atp = @(); $sl = @(); $sa = @(); $ap = @(); $mal = @(); $spam = @(); $atpo = $null
    try { $eop = @(Get-EOPProtectionPolicyRule | Select-Object Name, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs) } catch { }
    try { $atp = @(Get-ATPProtectionPolicyRule | Select-Object Name, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs) } catch { }
    try { $ap = @(Get-AntiPhishPolicy | Select-Object Name, IsDefault, Enabled, EnableTargetedUserProtection, EnableTargetedDomainsProtection, EnableOrganizationDomainsProtection, EnableMailboxIntelligence, EnableMailboxIntelligenceProtection, EnableSpoofIntelligence, PhishThresholdLevel, @{ n = 'TargetedUsers'; e = { @($_.TargetedUsersToProtect).Count } }, DmarcQuarantineAction, DmarcRejectAction, HonorDmarcPolicy) } catch { }
    try { $sl = @(Get-SafeLinksPolicy | Select-Object Name, EnableSafeLinksForEmail, EnableSafeLinksForTeams, EnableSafeLinksForOffice, ScanUrls, DeliverMessageAfterScan, TrackClicks, AllowClickThrough) } catch { }
    try { $sa = @(Get-SafeAttachmentPolicy | Select-Object Name, Enable, Action, Redirect, ActionOnError) } catch { }
    try { $atpo = Get-AtpPolicyForO365 | Select-Object EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen } catch { }
    try { $mal = @(Get-MalwareFilterPolicy | Select-Object Name, IsDefault, EnableFileFilter, ZapEnabled, @{ n = 'FileTypes'; e = { @($_.FileTypes).Count } }) } catch { }
    try { $spam = @(Get-HostedContentFilterPolicy | Select-Object Name, IsDefault, SpamAction, HighConfidenceSpamAction, PhishSpamAction, HighConfidencePhishAction, BulkThreshold, QuarantineRetentionPeriod, EnableEndUserSpamNotifications, @{ n = 'AllowedSenderDomains'; e = { @($_.AllowedSenderDomains).Count } }) } catch { }
    Save-CERRaw -Name 'threatpolicies' -Object ([ordered]@{ EOPPreset = $eop; DefenderPreset = $atp; AntiPhish = $ap; SafeLinks = $sl; SafeAttachments = $sa; AtpForO365 = $atpo; Malware = $mal; Spam = $spam })
    $presetOn = @($eop + $atp | Where-Object { $_.State -eq 'Enabled' })
    $apOn = @($ap | Where-Object { $_.Enabled -and $_.EnableMailboxIntelligenceProtection -and ($_.EnableTargetedUserProtection -or $_.EnableOrganizationDomainsProtection) })
    $hasDefender = ($sl.Count -gt 0 -or $sa.Count -gt 0)
    $flag = if ($presetOn.Count -or $apOn.Count) { 'OK' } else { 'Attention' }
    Add-CEREvidence -Control 'M365-03' -Flag $flag -Evidence ("Preset security policies enabled: {0} ({1}). Anti-phish policies with impersonation + mailbox intelligence protection: {2}/{3} ({4}); Defender for Office 365 {5}: Safe Links policies {6}, Safe Attachments {7}, SPO/Teams/OneDrive protection {8}, Safe Documents {9}; malware policies with common-attachment filter {10}/{11}; spam policies {12} (allowed sender domains total {13}). If Mimecast is the gateway, these are defence-in-depth." -f $presetOn.Count, (Join-CERList ($presetOn | ForEach-Object { $_.Name }) 3), $apOn.Count, $ap.Count, (Join-CERList ($apOn | ForEach-Object { "{0} (users {1}, threshold {2})" -f $_.Name, $_.TargetedUsers, $_.PhishThresholdLevel }) 3), $(if ($hasDefender) { 'present' } else { 'not present/licensed' }), $sl.Count, $sa.Count, $(if ($atpo) { $atpo.EnableATPForSPOTeamsODB } else { 'n/a' }), $(if ($atpo) { $atpo.EnableSafeDocs } else { 'n/a' }), @($mal | Where-Object EnableFileFilter).Count, $mal.Count, $spam.Count, (($spam | Measure-Object AllowedSenderDomains -Sum).Sum))
}

Invoke-CERSection -Collector $C -Section 'Mailboxes' -Script {
    $mbx = @(Get-EXOMailbox -ResultSize Unlimited -PropertySets Minimum, Delivery, Audit, Hold, Archive -Properties WhenCreated, ExternalDirectoryObjectId, RetentionPolicy, RecipientTypeDetails, LitigationHoldEnabled, AuditEnabled)
    $user = @($mbx | Where-Object { $_.RecipientTypeDetails -eq 'UserMailbox' }); $shared = @($mbx | Where-Object { $_.RecipientTypeDetails -eq 'SharedMailbox' }); $room = @($mbx | Where-Object { $_.RecipientTypeDetails -in 'RoomMailbox', 'EquipmentMailbox' })
    $domains = @($script:acceptedDomains | ForEach-Object { $_.DomainName.ToLower() })
    $fwd = @($mbx | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
    $fwdExt = @($fwd | Where-Object { $_.ForwardingSmtpAddress -and ($domains -notcontains (($_.ForwardingSmtpAddress -replace '^smtp:', '') -split '@')[-1].ToLower()) })
    $auditOff = @($mbx | Where-Object { $_.AuditEnabled -eq $false })
    $lit = @($mbx | Where-Object LitigationHoldEnabled)
    $archive = @($user | Where-Object { "$($_.ArchiveStatus)" -eq 'Active' })
    # shared mailbox sign-in state from Entra raw (if the Entra collector ran in this run)
    $entraUsers = Get-CERRaw -Collector 'entra' -Name 'users'
    $sharedEnabled = @(); $sharedLicensed = @()
    if ($entraUsers) {
        $map = @{}; foreach ($u in $entraUsers) { $map[$u.id] = $u }
        foreach ($s in $shared) { $u = $map[$s.ExternalDirectoryObjectId]; if ($u -and $u.accountEnabled) { $sharedEnabled += $s.PrimarySmtpAddress }; if ($u -and $u.licenses -gt 0) { $sharedLicensed += $s.PrimarySmtpAddress } }
    }
    # inactivity via statistics (capped)
    $inactive = @(); $checked = 0
    $sample = @($user | Select-Object -First $MaxMailboxStats)
    foreach ($m in $sample) {
        try { $st = Get-EXOMailboxStatistics -Identity $m.ExchangeGuid -Properties LastUserActionTime -ErrorAction Stop; $checked++; $lua = $st.LastUserActionTime; if (-not $lua -or $lua -lt $now.AddDays(-$StaleDays)) { $inactive += [pscustomobject]@{ Mailbox = $m.PrimarySmtpAddress; LastUserAction = $lua; Created = $m.WhenCreated } } } catch { }
    }
    $inactiveOld = @($inactive | Where-Object { $_.Created -lt $now.AddDays(-$StaleDays) })
    $rulesExt = @(); $rulesChecked = 0
    if ($CheckInboxRules) {
        foreach ($m in ($user | Select-Object -First 400)) {
            try { $r = @(Get-InboxRule -Mailbox $m.PrimarySmtpAddress -ErrorAction Stop | Where-Object { $_.Enabled -and ($_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo) }); $rulesChecked++; foreach ($x in $r) { $dest = @($x.ForwardTo + $x.ForwardAsAttachmentTo + $x.RedirectTo) -join ';'; if ($dest -match '@' -and ($domains | Where-Object { $dest -like "*@$_*" }).Count -eq 0) { $rulesExt += [pscustomobject]@{ Mailbox = $m.PrimarySmtpAddress; Rule = $x.Name; To = $dest } } } } catch { }
        }
    }
    Save-CERRaw -Name 'mailboxes' -Object ([ordered]@{ Total = $mbx.Count; User = $user.Count; Shared = $shared.Count; Room = $room.Count; Forwarding = @($fwd | Select-Object PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward); ForwardingExternal = @($fwdExt | ForEach-Object { $_.PrimarySmtpAddress }); AuditOff = $auditOff.Count; LitigationHold = $lit.Count; ArchiveActive = $archive.Count; SharedSignInEnabled = $sharedEnabled; SharedLicensed = $sharedLicensed; InactiveChecked = $checked; Inactive = $inactiveOld; InboxRulesExternal = $rulesExt; InboxRulesChecked = $rulesChecked })
    $flag = if ($fwdExt.Count -or $sharedEnabled.Count -or $rulesExt.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'M365-04' -Flag $flag -Evidence ("Mailboxes: {0} user, {1} shared, {2} room/equipment. Mailbox-level forwarding: {3}, to external domains: {4} ({5}). Shared mailboxes with sign-in still enabled: {6} ({7}){8}. Inactive user mailboxes (> {9} days, of {10} checked): {11} ({12}). Inbox rules forwarding externally: {13}{14}." -f $user.Count, $shared.Count, $room.Count, $fwd.Count, $fwdExt.Count, (Join-CERList ($fwdExt | ForEach-Object { $_.PrimarySmtpAddress }) 5), $sharedEnabled.Count, (Join-CERList $sharedEnabled 5), $(if (-not $entraUsers) { ' [Entra user data not in this run - sign-in state unknown]' } else { '' }), $StaleDays, $checked, $inactiveOld.Count, (Join-CERList ($inactiveOld | ForEach-Object { $_.Mailbox }) 5), $rulesExt.Count, $(if (-not $CheckInboxRules) { ' [not checked - use -CheckInboxRules]' } else { " (of $rulesChecked mailboxes)" }))
    Add-CEREvidence -Control 'M365-08' -Flag Info -Evidence ("Litigation hold on {0} mailboxes; online archive active on {1}/{2} user mailboxes; mailbox auditing explicitly off on {3}." -f $lit.Count, $archive.Count, $user.Count, $auditOff.Count)
    if ($sharedLicensed.Count) { Add-CEREvidence -Control 'M365-10' -Flag Attention -Evidence ("{0} shared mailboxes carry a licence (only needed for archive/hold or > 50 GB): {1}" -f $sharedLicensed.Count, (Join-CERList $sharedLicensed 5)) }
    if ($inactiveOld.Count) { Add-CEREvidence -Control 'M365-10' -Flag Attention -Evidence ("{0} user mailboxes inactive > {1} days (candidates for licence removal / conversion to shared)." -f $inactiveOld.Count, $StaleDays) }
}

Invoke-CERSection -Collector $C -Section 'MobileAndSharing' -Script {
    $mdp = @(Get-MobileDeviceMailboxPolicy | Select-Object Name, IsDefault, PasswordEnabled, MinPasswordLength, AllowNonProvisionableDevices, MaxInactivityTimeLock, DeviceEncryptionEnabled, AllowSimplePassword)
    $sp = @(Get-SharingPolicy | Select-Object Name, Default, Enabled, Domains)
    $or = @(Get-OrganizationRelationship | Select-Object Name, DomainNames, Enabled, FreeBusyAccessEnabled, MailboxMoveEnabled)
    $owa = @(Get-OwaMailboxPolicy | Select-Object Name, IsDefault, ExternalImageProxyEnabled, ThirdPartyFileProvidersEnabled, AdditionalStorageProvidersAvailable, ConditionalAccessPolicy, DirectFileAccessOnPublicComputersEnabled)
    Save-CERRaw -Name 'mobilesharing' -Object ([ordered]@{ MobileDevicePolicies = $mdp; SharingPolicies = $sp; OrgRelationships = $or; OwaPolicies = $owa })
    $def = $mdp | Where-Object IsDefault | Select-Object -First 1
    Add-CEREvidence -Control 'END-14' -Flag Info -Evidence ("Exchange mobile device mailbox policy (default '{0}'): password required={1}, min length={2}, non-provisionable devices allowed={3}, inactivity lock={4}, device encryption={5}. Intune app protection/CA supersedes this where present." -f $(if ($def) { $def.Name } else { 'n/a' }), $(if ($def) { $def.PasswordEnabled } else { '' }), $(if ($def) { $def.MinPasswordLength } else { '' }), $(if ($def) { $def.AllowNonProvisionableDevices } else { '' }), $(if ($def) { $def.MaxInactivityTimeLock } else { '' }), $(if ($def) { $def.DeviceEncryptionEnabled } else { '' }))
    Add-CEREvidence -Control 'M365-06' -Flag Info -Evidence ("OWA policies: third-party file providers enabled on {0}/{1}; additional storage providers on {2}; calendar sharing policy domains: {3}." -f @($owa | Where-Object ThirdPartyFileProvidersEnabled).Count, $owa.Count, @($owa | Where-Object AdditionalStorageProvidersAvailable).Count, (Join-CERList (($sp | Where-Object Default).Domains) 4))
}

if (-not $SkipPurview) {
    Invoke-CERSection -Collector $C -Section 'Purview' -Script {
        $p = @{ UserPrincipalName = $UserPrincipalName; ShowBanner = $false; ErrorAction = 'Stop' }
        if ($DelegatedOrganization) { $p['DelegatedOrganization'] = $DelegatedOrganization }
        Connect-IPPSSession @p
        $ret = @(Get-RetentionCompliancePolicy -DistributionDetail | Select-Object Name, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation, TeamsChatLocation, TeamsChannelLocation, ModernGroupLocation, DistributionStatus)
        $dlp = @(Get-DlpCompliancePolicy | Select-Object Name, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation, TeamsLocation, EndpointDlpLocation, Priority)
        $labels = @(); try { $labels = @(Get-Label | Select-Object DisplayName, Name, ContentType, Disabled) } catch { }
        $labelPol = @(); try { $labelPol = @(Get-LabelPolicy | Select-Object Name, Enabled, ExchangeLocation, Labels) } catch { }
        $retLabels = @(); try { $retLabels = @(Get-ComplianceTag | Select-Object Name, RetentionDuration, RetentionAction) } catch { }
        Save-CERRaw -Name 'purview' -Object ([ordered]@{ Retention = $ret; DLP = $dlp; SensitivityLabels = $labels; LabelPolicies = $labelPol; RetentionLabels = $retLabels })
        function _loc { param($pol, $prop) $v = $pol.$prop; if ($v -and (@($v) -join ',') -match 'All') { 'All' } elseif ($v) { "$(@($v).Count) scoped" } else { '-' } }
        $retTxt = @($ret | Where-Object Enabled | ForEach-Object { "{0} [EXO {1}, SPO {2}, OD {3}, Teams {4}/{5}]" -f $_.Name, (_loc $_ 'ExchangeLocation'), (_loc $_ 'SharePointLocation'), (_loc $_ 'OneDriveLocation'), (_loc $_ 'TeamsChatLocation'), (_loc $_ 'TeamsChannelLocation') })
        $dlpEnforce = @($dlp | Where-Object { $_.Enabled -and $_.Mode -eq 'Enable' }); $dlpTest = @($dlp | Where-Object { $_.Enabled -and $_.Mode -like 'Test*' })
        $flag = if (@($ret | Where-Object Enabled).Count -and ($dlpEnforce.Count -or $dlpTest.Count)) { 'OK' } else { 'Attention' }
        Add-CEREvidence -Control 'M365-08' -Flag $flag -Evidence ("Purview: retention policies {0} enabled ({1}); DLP policies {2} (enforced {3}, test mode {4}: {5}); sensitivity labels {6} ({7} published via {8} policies); retention labels {9}." -f @($ret | Where-Object Enabled).Count, (Join-CERList $retTxt 4), $dlp.Count, $dlpEnforce.Count, $dlpTest.Count, (Join-CERList ($dlp | ForEach-Object { $_.Name }) 4), $labels.Count, (($labelPol | ForEach-Object { @($_.Labels).Count } | Measure-Object -Sum).Sum), $labelPol.Count, $retLabels.Count)
    }
}
try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
Complete-CERCollector
