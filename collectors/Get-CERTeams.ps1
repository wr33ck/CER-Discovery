#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (optional): Microsoft Teams governance via the MicrosoftTeams module. Feeds M365-07.
.EXAMPLE
  .\Get-CERTeams.ps1 -Client C-003 -RunId 20260905-0900 -TenantId <customer tenant id>
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Client, [string]$OutputRoot, [string]$RunId, [Parameter(Mandatory)][string]$TenantId, [switch]$UseDeviceCode)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Teams' -RunId $RunId
$C = 'Teams'
if (-not (Test-CERModule -Name MicrosoftTeams -Collector $C)) { Complete-CERCollector; return }
Import-Module MicrosoftTeams -ErrorAction Stop
Invoke-CERSection -Collector $C -Section 'Connect' -Script { $p = @{ TenantId = $TenantId; ErrorAction = 'Stop' }; if ($UseDeviceCode) { $p['UseDeviceCode'] = $true }; Connect-MicrosoftTeams @p | Out-Null }
Invoke-CERSection -Collector $C -Section 'Governance' -Script {
    $fed = Get-CsTenantFederationConfiguration
    $client = Get-CsTeamsClientConfiguration
    $meet = Get-CsTeamsMeetingPolicy -Identity Global
    $app = Get-CsTeamsAppPermissionPolicy -Identity Global
    $ext = Get-CsExternalAccessPolicy -Identity Global
    $msg = Get-CsTeamsMessagingPolicy -Identity Global
    $guestMeet = $null; try { $guestMeet = Get-CsTeamsGuestMeetingConfiguration } catch { }
    Save-CERRaw -Name 'governance' -Object ([ordered]@{ Federation = ($fed | Select-Object AllowFederatedUsers, AllowTeamsConsumer, AllowTeamsConsumerInbound, AllowPublicUsers, AllowedDomains, BlockedDomains, SharedSipAddressSpace); Client = ($client | Select-Object AllowGuestUser, AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte, AllowEmailIntoChannel); Meeting = ($meet | Select-Object AllowAnonymousUsersToJoinMeeting, AllowAnonymousUsersToStartMeeting, AutoAdmittedUsers, AllowPSTNUsersToBypassLobby, AllowExternalParticipantGiveRequestControl, AllowCloudRecording, DesignatedPresenterRoleMode, AllowExternalNonTrustedMeetingChat); AppPermission = ($app | Select-Object DefaultCatalogAppsType, GlobalCatalogAppsType, PrivateCatalogAppsType); ExternalAccess = ($ext | Select-Object EnableFederationAccess, EnableTeamsConsumerAccess, EnablePublicCloudAccess, EnableXmppAccess); Messaging = ($msg | Select-Object AllowUserDeleteMessage, AllowUserEditMessage, AllowUrlPreviews, AllowGiphy); GuestMeeting = $guestMeet })
    $allowedDom = @($fed.AllowedDomains); $openFed = ($fed.AllowFederatedUsers -and ($allowedDom.Count -eq 0 -or "$($allowedDom)" -match 'AllowAllKnownDomains'))
    $lobby = "$($meet.AutoAdmittedUsers)"; $lobbyOk = ($lobby -in 'EveryoneInCompany', 'EveryoneInCompanyExcludingGuests', 'OrganizerOnly', 'InvitedUsers')
    $appOpen = ("$($app.GlobalCatalogAppsType)" -eq 'AllowedAppList') -eq $false
    $flag = if ($openFed -and $fed.AllowTeamsConsumer) { 'Attention' } elseif (-not $lobbyOk -or $meet.AllowAnonymousUsersToStartMeeting) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'M365-07' -Flag $flag -Evidence ("Teams: federation allowed={0} (allowed domains {1}, blocked {2}), Teams consumer access={3}, public Skype users={4}; guest access={5}; meetings: anonymous join={6}, anonymous can start={7}, lobby auto-admit='{8}', PSTN bypass lobby={9}; third-party storage in Teams (Dropbox/Box/GDrive)={10}/{11}/{12}; app permission policy (global): Microsoft apps {13}, third-party apps {14}, custom apps {15}." -f $fed.AllowFederatedUsers, $(if ($allowedDom.Count) { $allowedDom.Count } else { 'all' }), @($fed.BlockedDomains).Count, $fed.AllowTeamsConsumer, $fed.AllowPublicUsers, $client.AllowGuestUser, $meet.AllowAnonymousUsersToJoinMeeting, $meet.AllowAnonymousUsersToStartMeeting, $lobby, $meet.AllowPSTNUsersToBypassLobby, $client.AllowDropBox, $client.AllowBox, $client.AllowGoogleDrive, $app.DefaultCatalogAppsType, $app.GlobalCatalogAppsType, $app.PrivateCatalogAppsType)
}
try { Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null } catch { }
Complete-CERCollector
