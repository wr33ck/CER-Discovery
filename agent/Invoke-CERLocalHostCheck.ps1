<#
.SYNOPSIS
  CER-Discovery local host check (Windows PowerShell 5.1+, no modules, no internet).
  Collects the host-level facts that map to the Client Environment Review controls
  (Essential Eight endpoint settings, patch age, agents present, hardening, local admins, shares, certs, EoL software).

.USAGE
  RMM (N-central / NinjaOne), run as SYSTEM, 64-bit PowerShell:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File Invoke-CERLocalHostCheck.ps1 -OutputPath "C:\ProgramData\CER"
      (add -OutputShare "\\FILESERVER\CER$" to also drop a copy on a share; add -IncludeWindowsUpdateSearch for a live WU scan, +30-120 s)
  Interactive: .\Invoke-CERLocalHostCheck.ps1 | Out-File host.json
  Remote:      the Servers collector loads the function block below and runs it through Invoke-Command.

.OUTPUT
  JSON, one file per host: <OutputPath>\<HOSTNAME>.cer-host.json  (also written to stdout unless -Quiet)
  Import a folder of these with  agent\Import-CERLocalHostResults.ps1  or  collectors\Get-CERWindowsServers.ps1 -ImportOnly
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$OutputShare,
    [switch]$IncludeWindowsUpdateSearch,
    [switch]$SkipInstalledSoftware,
    [switch]$Quiet
)

#region HOSTSTATE
function Get-CERHostState {
    [CmdletBinding()]
    param([switch]$IncludeWindowsUpdateSearch, [switch]$SkipInstalledSoftware)

    $ErrorActionPreference = 'SilentlyContinue'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $errors = New-Object System.Collections.ArrayList
    function _err { param($Area, $Msg) $null = $errors.Add([pscustomobject]@{ Area = $Area; Message = "$Msg" }) }
    function _reg { param($Path, $Name) try { $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop; return $p.$Name } catch { return $null } }
    function _regExists { param($Path) return (Test-Path -Path $Path) }
    function _svc { param($Name) try { return Get-Service -Name $Name -ErrorAction Stop } catch { return $null } }

    $out = [ordered]@{}
    $out.Meta = [ordered]@{ Hostname = $env:COMPUTERNAME; FQDN = $null; Domain = $null; PartOfDomain = $null; CollectedAt = (Get-Date).ToString('s'); RunAs = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME); PSVersion = $PSVersionTable.PSVersion.ToString(); ScriptVersion = '1.0'; IsAdmin = $null }
    try { $out.Meta.IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }

    # ---------------- System
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $enc = Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $ubr = $cv.UBR
        $fullBuild = if ($ubr) { "$($os.Version).$ubr" } else { $os.Version }
        $isVirtual = ($cs.Model -match 'Virtual|VMware|KVM|HVM|Xen|QEMU' -or $cs.Manufacturer -match 'VMware|Microsoft Corporation|QEMU|Xen|innotek|Nutanix|Red Hat')
        $chassis = @($enc.ChassisTypes)
        $isLaptop = ($chassis | Where-Object { $_ -in 8, 9, 10, 14, 30, 31, 32 }).Count -gt 0
        $productType = [int]$os.ProductType   # 1 workstation, 2 DC, 3 server
        $support = Get-CERWindowsSupport -Caption $os.Caption -Version $os.Version -ProductType $productType -EditionId $cv.EditionID
        try { $out.Meta.FQDN = ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName } catch { }
        $out.Meta.Domain = $cs.Domain; $out.Meta.PartOfDomain = [bool]$cs.PartOfDomain
        $entra = $null
        try { $ds = dsregcmd /status 2>$null; if ($ds) { $entra = [ordered]@{ AzureAdJoined = (($ds | Select-String 'AzureAdJoined\s*:\s*(\w+)').Matches.Groups[1].Value); DomainJoined = (($ds | Select-String 'DomainJoined\s*:\s*(\w+)').Matches.Groups[1].Value); MdmUrl = (($ds | Select-String 'MdmUrl\s*:\s*(\S+)').Matches.Groups[1].Value) } } } catch { }
        $out.System = [ordered]@{
            OS = $os.Caption; Version = $os.Version; Build = $fullBuild; DisplayVersion = $cv.DisplayVersion; EditionId = $cv.EditionID; ProductType = $productType
            InstallDate = $os.InstallDate; LastBoot = $os.LastBootUpTime; UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
            Manufacturer = $cs.Manufacturer; Model = $cs.Model; Serial = $bios.SerialNumber; BIOSDate = $bios.ReleaseDate; HardwareAgeYearsApprox = $(if ($bios.ReleaseDate) { [math]::Round(((Get-Date) - $bios.ReleaseDate).TotalDays / 365.25, 1) } else { $null }); IsVirtual = $isVirtual; IsLaptop = $isLaptop
            Architecture = $os.OSArchitecture; ProcessorCount = $cs.NumberOfLogicalProcessors; MemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            TimeZone = (Get-TimeZone).Id; Support = $support; Entra = $entra
            IPv4 = @((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress))
        }
    } catch { _err 'System' $_.Exception.Message }

    # ---------------- Patching
    try {
        $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending
        $last = $hf | Select-Object -First 1
        $pend = [ordered]@{
            Cbs = _regExists 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
            Wu = _regExists 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            FileRename = [bool](_reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')
            Ccm = $false
        }
        $pend.Any = ($pend.Cbs -or $pend.Wu -or $pend.FileRename)
        $wuServer = _reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
        $useWu = _reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'UseWUServer'
        $managedBy = 'Windows Update (unmanaged or ring policy)'
        if ($wuServer -and $useWu -eq 1) { $managedBy = "WSUS/RMM: $wuServer" }
        elseif (_regExists 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update') { $managedBy = 'Intune/MDM update policy' }
        $out.Patching = [ordered]@{
            LastHotfixDate = if ($last) { $last.InstalledOn } else { $null }; LastHotfixKB = if ($last) { $last.HotFixID } else { $null }; HotfixCount = @($hf).Count
            LastHotfixAgeDays = if ($last) { [int]((Get-Date) - $last.InstalledOn).TotalDays } else { $null }
            LastWUSuccessInstall = _reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' 'LastSuccessTime'
            LastWUSuccessDetect = _reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect' 'LastSuccessTime'
            WUServer = $wuServer; ManagedBy = $managedBy; PendingReboot = $pend; PendingUpdates = $null; PendingUpdateTitles = @()
        }
        if ($IncludeWindowsUpdateSearch) {
            try {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $res = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
                $out.Patching.PendingUpdates = $res.Updates.Count
                $out.Patching.PendingUpdateTitles = @($res.Updates | ForEach-Object { $_.Title } | Select-Object -First 25)
            } catch { _err 'WindowsUpdateSearch' $_.Exception.Message }
        }
    } catch { _err 'Patching' $_.Exception.Message }

    # ---------------- Services -> agents and roles
    try {
        $svcs = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName
        $agentMap = @(
            @{ Cat = 'EDR'; Product = 'CrowdStrike Falcon'; Match = '^CSFalconService$' },
            @{ Cat = 'EDR'; Product = 'Microsoft Defender for Endpoint (Sense)'; Match = '^Sense$' },
            @{ Cat = 'EDR'; Product = 'Trend Micro (Apex One / Worry-Free)'; Match = '^(ntrtscan|tmlisten|TmCCSF|TMBMServer|Trend Micro .*|TmPfw)$' },
            @{ Cat = 'EDR'; Product = 'Trend Micro Deep Security'; Match = '^ds_agent$' },
            @{ Cat = 'EDR'; Product = 'SentinelOne'; Match = '^SentinelAgent$' },
            @{ Cat = 'EDR'; Product = 'Sophos'; Match = '^Sophos (Endpoint Defense|MCS Client|File Scanner|Health Service)' },
            @{ Cat = 'EDR'; Product = 'Cylance'; Match = '^CylanceSvc$' },
            @{ Cat = 'EDR'; Product = 'ESET'; Match = '^(ekrn|efwd)$' },
            @{ Cat = 'EDR'; Product = 'Bitdefender'; Match = '^EPSecurityService$|^EPProtectedService$' },
            @{ Cat = 'EDR'; Product = 'Webroot'; Match = '^WRSVC$' },
            @{ Cat = 'AV';  Product = 'Microsoft Defender Antivirus'; Match = '^WinDefend$' },
            @{ Cat = 'MDR'; Product = 'Huntress'; Match = '^Huntress(Agent|Updater|Rio)$' },
            @{ Cat = 'MDR'; Product = 'Rapid7 Insight Agent'; Match = '^ir_agent$' },
            @{ Cat = 'MDR'; Product = 'Blackpoint SNAP'; Match = '^SnapAgent' },
            @{ Cat = 'AppControl'; Product = 'Airlock Digital'; Match = 'Airlock' },
            @{ Cat = 'AppControl'; Product = 'ThreatLocker'; Match = '^ThreatLockerService$' },
            @{ Cat = 'RMM'; Product = 'N-able N-central Agent'; Match = '^Windows Agent Service$|^Windows Agent Maintenance Service$' },
            @{ Cat = 'RMM'; Product = 'N-able N-sight / Advanced Monitoring Agent'; Match = '^Advanced Monitoring Agent|^BASupportExpressStandaloneService' },
            @{ Cat = 'RMM'; Product = 'N-able Take Control'; Match = '^BASupportExpressSrvcUpdater|^MSPAnywhere' },
            @{ Cat = 'RMM'; Product = 'NinjaOne'; Match = '^NinjaRMMAgent$' },
            @{ Cat = 'RMM'; Product = 'Datto RMM'; Match = '^CagService$' },
            @{ Cat = 'RMM'; Product = 'ConnectWise Automate'; Match = '^LTService$' },
            @{ Cat = 'RMM'; Product = 'Kaseya'; Match = '^KaseyaAgent|^AgentMon' },
            @{ Cat = 'RMM'; Product = 'Intune Management Extension'; Match = '^IntuneManagementExtension$' },
            @{ Cat = 'RMM'; Product = 'SCCM/ConfigMgr client'; Match = '^CcmExec$' },
            @{ Cat = 'Backup'; Product = 'Veeam Agent for Windows'; Match = '^VeeamEndpointBackupSvc$' },
            @{ Cat = 'Backup'; Product = 'Veeam Backup & Replication (server/proxy/transport)'; Match = '^Veeam(BackupSvc|TransportSvc|DeploySvc|MountSvc)$' },
            @{ Cat = 'Backup'; Product = 'Azure Backup (MARS)'; Match = '^obengine$' },
            @{ Cat = 'Backup'; Product = 'Datto/ShadowProtect'; Match = '^ShadowProtectSvc$|^DattoBackupAgent' },
            @{ Cat = 'Backup'; Product = 'Acronis'; Match = '^AcronisAgent|^AcrSch2Svc' },
            @{ Cat = 'RemoteTool'; Product = 'TeamViewer'; Match = '^TeamViewer' },
            @{ Cat = 'RemoteTool'; Product = 'AnyDesk'; Match = '^AnyDesk' },
            @{ Cat = 'RemoteTool'; Product = 'ScreenConnect/ConnectWise Control'; Match = '^ScreenConnect Client' },
            @{ Cat = 'RemoteTool'; Product = 'Splashtop'; Match = '^SplashtopRemoteService' },
            @{ Cat = 'RemoteTool'; Product = 'LogMeIn'; Match = '^LMIGuardianSvc|^LogMeIn' },
            @{ Cat = 'RemoteTool'; Product = 'RustDesk'; Match = '^RustDesk' },
            @{ Cat = 'RemoteTool'; Product = 'GoToAssist/GoTo'; Match = '^GoTo' },
            @{ Cat = 'RemoteTool'; Product = 'BeyondTrust/Bomgar'; Match = 'bomgar' },
            @{ Cat = 'RemoteTool'; Product = 'Chrome Remote Desktop'; Match = '^chromoting$' },
            @{ Cat = 'Other'; Product = 'Mimecast Security Agent'; Match = 'Mimecast' },
            @{ Cat = 'Other'; Product = 'LogicMonitor Collector'; Match = '^logicmonitor' },
            @{ Cat = 'Other'; Product = 'SolarWinds Agent'; Match = '^SolarWinds' },
            @{ Cat = 'Other'; Product = 'ControlUp Agent'; Match = '^cuAgent$' },
            @{ Cat = 'Other'; Product = 'VMware Tools'; Match = '^VMTools$' },
            @{ Cat = 'Other'; Product = 'Hyper-V Integration'; Match = '^vmicheartbeat$' }
        )
        $found = New-Object System.Collections.ArrayList
        foreach ($m in $agentMap) {
            $hits = @($svcs | Where-Object { $_.Name -match $m.Match -or $_.DisplayName -match $m.Match })
            if ($hits.Count -gt 0) {
                $null = $found.Add([pscustomobject]@{ Category = $m.Cat; Product = $m.Product; Services = @($hits | ForEach-Object { "{0}={1}" -f $_.Name, $_.State }) ; Running = (@($hits | Where-Object { $_.State -eq 'Running' }).Count -gt 0) })
            }
        }
        $byCat = @{}
        foreach ($c in 'EDR', 'AV', 'MDR', 'AppControl', 'RMM', 'Backup', 'RemoteTool', 'Other') { $byCat[$c] = @($found | Where-Object { $_.Category -eq $c } | Select-Object -ExpandProperty Product -Unique) }
        $out.Agents = [ordered]@{ EDR = $byCat.EDR; AV = $byCat.AV; MDR = $byCat.MDR; AppControl = $byCat.AppControl; RMM = $byCat.RMM; Backup = $byCat.Backup; RemoteTools = $byCat.RemoteTool; Other = $byCat.Other; Detail = @($found) }

        $sqlInstances = @()
        try {
            $inst = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction Stop
            foreach ($p in $inst.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
                $setup = Get-ItemProperty ("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\Setup" -f $p.Value) -ErrorAction SilentlyContinue
                $sup = Get-CERSqlSupport -Version $setup.Version
                $sqlInstances += [pscustomobject]@{ Instance = $p.Name; Version = $setup.Version; PatchLevel = $setup.PatchLevel; Edition = $setup.Edition; Product = $sup.Name; Supported = $sup.Supported; Note = $sup.Note }
            }
        } catch { }
        $exch = $null
        try { $ex = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' -ErrorAction Stop; $exch = "15.{0}.{1}.{2}" -f $ex.MsiProductMinor, $ex.MsiBuildMajor, $ex.MsiBuildMinor } catch { }
        $sharedPrinters = 0
        try { $sharedPrinters = @(Get-CimInstance Win32_Printer | Where-Object { $_.Shared }).Count } catch { }
        $rdsHost = $false
        try { $rdsHost = ((_reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'TSAppCompat') -eq 1) } catch { }
        $out.Roles = [ordered]@{
            IsDomainController = ($out.System.ProductType -eq 2); HasSql = ($sqlInstances.Count -gt 0); SqlInstances = $sqlInstances
            HasIIS = [bool](_svc 'W3SVC'); HasExchange = [bool]$exch; ExchangeBuild = $exch; HasHyperV = [bool](_svc 'vmms'); HasADSync = [bool](_svc 'ADSync')
            HasVeeamBackupServer = [bool](_svc 'VeeamBackupSvc'); HasCertSvc = [bool](_svc 'CertSvc'); HasDhcp = [bool](_svc 'DHCPServer'); HasDns = [bool](_svc 'DNS')
            HasNPS = [bool](_svc 'IAS'); HasWSUS = [bool](_svc 'WsusService'); HasFileShares = $false; SpoolerRunning = ((_svc 'Spooler').Status -eq 'Running'); SharedPrinters = $sharedPrinters; IsRdsHost = $rdsHost
            HasWinRM = ((_svc 'WinRM').Status -eq 'Running')
        }
    } catch { _err 'Services' $_.Exception.Message }

    # ---------------- Defender
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $mp = Get-MpComputerStatus
            $pref = Get-MpPreference
            $asr = @()
            if ($pref.AttackSurfaceReductionRules_Ids) {
                for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
                    $id = $pref.AttackSurfaceReductionRules_Ids[$i]; $act = $pref.AttackSurfaceReductionRules_Actions[$i]
                    $asr += [pscustomobject]@{ Id = $id; Name = (Get-CERAsrRuleName $id); Action = [int]$act; ActionName = @{0 = 'Off'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }[[int]$act] }
                }
            }
            $out.Defender = [ordered]@{
                Present = $true; AMRunningMode = $mp.AMRunningMode; AntivirusEnabled = $mp.AntivirusEnabled; RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
                IsTamperProtected = $mp.IsTamperProtected; SignatureAgeDays = $mp.AntivirusSignatureAge; EngineVersion = $mp.AMEngineVersion; ProductVersion = $mp.AMProductVersion
                MAPSReporting = $pref.MAPSReporting; SubmitSamplesConsent = $pref.SubmitSamplesConsent; PUAProtection = $pref.PUAProtection; NetworkProtection = $pref.EnableNetworkProtection; ControlledFolderAccess = $pref.EnableControlledFolderAccess
                CloudBlockLevel = $pref.CloudBlockLevel; ASR = $asr; ASRBlockCount = @($asr | Where-Object { $_.Action -eq 1 }).Count; ASRAuditCount = @($asr | Where-Object { $_.Action -eq 2 }).Count
            }
        } else { $out.Defender = [ordered]@{ Present = $false } }
    } catch { _err 'Defender' $_.Exception.Message }

    # ---------------- Hardening
    try {
        $h = [ordered]@{}
        try { $smb = Get-SmbServerConfiguration; $h.SMB1Enabled = $smb.EnableSMB1Protocol; $h.SMBSigningRequired = $smb.RequireSecuritySignature; $h.SMBEncryptData = $smb.EncryptData } catch { $h.SMB1Enabled = $null }
        try { $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop; $h.SMB1FeatureState = "$($f.State)" } catch { $h.SMB1FeatureState = $null }
        foreach ($proto in '1.0', '1.1', '1.2', '1.3') {
            $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS $proto\Server"
            $en = _reg $k 'Enabled'; $dis = _reg $k 'DisabledByDefault'
            $h["TLS$($proto.Replace('.',''))Server"] = if ($null -eq $en -and $null -eq $dis) { 'OS default' } elseif ($en -eq 0) { 'Disabled' } else { 'Enabled' }
        }
        $h.RDPEnabled = ((_reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0)
        $h.RDPNLARequired = ((_reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1)
        $h.RDPSecurityLayer = _reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer'
        $h.RDPPort = _reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
        try { $fw = Get-NetFirewallProfile; $h.Firewall = [ordered]@{ Domain = ($fw | ? Name -eq 'Domain').Enabled; Private = ($fw | ? Name -eq 'Private').Enabled; Public = ($fw | ? Name -eq 'Public').Enabled }; $h.FirewallAllProfilesOn = (@($fw | Where-Object { -not $_.Enabled }).Count -eq 0) } catch { }
        $h.UAC = [ordered]@{ EnableLUA = (_reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'); ConsentPromptBehaviorAdmin = (_reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin') }
        $h.LmCompatibilityLevel = _reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
        $h.LDAPClientIntegrity = _reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity'
        $h.LLMNRDisabled = ((_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0)
        $h.WDigestUseLogonCredential = _reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        $h.AutoLogonConfigured = ((_reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon') -eq '1')
        try { $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; $h.CredentialGuardRunning = (@($dg.SecurityServicesRunning) -contains 1); $h.VBSStatus = $dg.VirtualizationBasedSecurityStatus; $h.WDAC = [ordered]@{ CodeIntegrityPolicyEnforcementStatus = $dg.CodeIntegrityPolicyEnforcementStatus; UsermodeCodeIntegrityPolicyEnforcementStatus = $dg.UsermodeCodeIntegrityPolicyEnforcementStatus } } catch { }
        try { $h.SecureBoot = Confirm-SecureBootUEFI } catch { $h.SecureBoot = $null }
        try { $tpm = Get-Tpm; $h.TPM = [ordered]@{ Present = $tpm.TpmPresent; Ready = $tpm.TpmReady; Version = (Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm).SpecVersion } } catch { }
        try {
            if ($out.System.ProductType -eq 1) { $f2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop; $h.PowerShellV2 = "$($f2.State)" }
            else { $f2 = Get-WindowsFeature -Name PowerShell-V2 -ErrorAction Stop; $h.PowerShellV2 = if ($f2.Installed) { 'Enabled' } else { 'Disabled' } }
        } catch { $h.PowerShellV2 = $null }
        $h.PSLogging = [ordered]@{
            ScriptBlock = ((_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1)
            Module = ((_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq 1)
            Transcription = ((_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting') -eq 1)
        }
        $h.CmdLineAuditing = ((_reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1)
        try { $ie = Get-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -ErrorAction Stop; $h.IE11Feature = "$($ie.State)" } catch { $h.IE11Feature = 'Not present' }
        $lapsIntune = _regExists 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
        $lapsGpo = _regExists 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
        $lapsLegacy = _reg 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
        $backupDir = $null
        if ($lapsIntune) { $backupDir = _reg 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory' } elseif ($lapsGpo) { $backupDir = _reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory' }
        $h.LAPS = [ordered]@{ WindowsLAPSPolicy = ($lapsIntune -or $lapsGpo); PolicySource = $(if ($lapsIntune) { 'Intune CSP' } elseif ($lapsGpo) { 'GPO' } else { $null }); BackupDirectory = $(if ($null -ne $backupDir) { @{ 0 = 'Disabled'; 1 = 'Active Directory'; 2 = 'Entra ID' }[[int]$backupDir] } else { $null }); LegacyLAPS = ($lapsLegacy -eq 1); Configured = ($lapsIntune -or $lapsGpo -or ($lapsLegacy -eq 1)) }
        $userPol = @()
        try {
            foreach ($hive in (Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' })) {
                $sid = $hive.PSChildName
                $userPol += [pscustomobject]@{ Sid = $sid; ScreenSaveTimeOut = (_reg "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\Control Panel\Desktop" 'ScreenSaveTimeOut'); ScreenSaverIsSecure = (_reg "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\Control Panel\Desktop" 'ScreenSaverIsSecure') }
            }
        } catch { }
        $h.ScreenLock = [ordered]@{ MachineInactivityTimeoutSecs = (_reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'); UserPolicies = $userPol }
        $h.USBStorage = [ordered]@{ DenyAllRemovable = (_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' 'Deny_All'); USBSTORStart = (_reg 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start'); RemovableDiskDenyWrite = (_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' 'Deny_Write') }
        $h.PointAndPrint = [ordered]@{ RestrictDriverInstallationToAdministrators = (_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators'); NoWarningNoElevationOnInstall = (_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'NoWarningNoElevationOnInstall'); UpdatePromptSettings = (_reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'UpdatePromptSettings') }
        try { $sec = Get-WinEvent -ListLog Security -ErrorAction Stop; $h.SecurityLogMaxMB = [math]::Round($sec.MaximumSizeInBytes / 1MB); $h.SecurityLogOldest = $sec.OldestRecordNumber } catch { }
        try {
            $ap = auditpol /get /category:* /r 2>$null | ConvertFrom-Csv
            $want = 'Process Creation', 'Logon', 'Logoff', 'Account Lockout', 'Credential Validation', 'Kerberos Authentication Service', 'Security Group Management', 'User Account Management', 'Audit Policy Change', 'Special Logon', 'Other Object Access Events', 'Sensitive Privilege Use', 'PNP Activity'
            $h.AuditPolicy = @{}
            foreach ($w in $want) { $row = $ap | Where-Object { $_.Subcategory -eq $w } | Select-Object -First 1; if ($row) { $h.AuditPolicy[$w] = $row.'Inclusion Setting' } }
        } catch { }
        if ($out.System.ProductType -eq 2) {
            $h.DC = [ordered]@{ LDAPServerIntegrity = (_reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'); LdapEnforceChannelBinding = (_reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'); NtlmMinServerSec = (_reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinServerSec'); RestrictNTLMInDomain = (_reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RestrictNTLMInDomain') }
        }
        $out.Hardening = $h
    } catch { _err 'Hardening' $_.Exception.Message }

    # ---------------- Office macro policy (HKLM + loaded user hives)
    try {
        $apps = 'word', 'excel', 'powerpoint', 'access', 'outlook', 'publisher', 'visio'
        function _macroFromRoot { param($Root)
            $r = [ordered]@{}
            foreach ($a in $apps) {
                $base = "$Root\Software\Policies\Microsoft\Office\16.0\$a\Security"
                $vba = _reg $base 'VBAWarnings'; $blk = _reg $base 'blockcontentexecutionfrominternet'
                $trusted = _reg "$base\Trusted Locations" 'AllowNetworkLocations'
                if ($null -ne $vba -or $null -ne $blk) { $r[$a] = [ordered]@{ VBAWarnings = $vba; VBAWarningsMeaning = @{1 = 'Enable all (unsafe)'; 2 = 'Disable with notification'; 3 = 'Disable except digitally signed'; 4 = 'Disable all without notification' }[[int]$vba]; BlockContentExecutionFromInternet = $blk; AllowNetworkTrustedLocations = $trusted } }
            }
            $r['_MacroRuntimeScanScope'] = _reg "$Root\Software\Policies\Microsoft\Office\16.0\Common\Security" 'MacroRuntimeScanScope'
            return $r
        }
        $office = [ordered]@{}
        $office.Installed = $null
        try { $c2r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction Stop; $office.Installed = [ordered]@{ Version = $c2r.VersionToReport; Channel = $c2r.CDNBaseUrl; Products = $c2r.ProductReleaseIds; Platform = $c2r.Platform } } catch { }
        $office.MachinePolicy = _macroFromRoot 'HKLM:'
        $office.UserPolicies = @()
        foreach ($hive in (Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' })) {
            $u = _macroFromRoot ("Registry::HKEY_USERS\{0}" -f $hive.PSChildName)
            if (($u.Keys | Where-Object { $_ -ne '_MacroRuntimeScanScope' }).Count -gt 0 -or $null -ne $u._MacroRuntimeScanScope) { $office.UserPolicies += [pscustomobject]@{ Sid = $hive.PSChildName; Policy = $u } }
        }
        $anyApp = @($office.MachinePolicy.Keys | Where-Object { $_ -ne '_MacroRuntimeScanScope' }).Count + @($office.UserPolicies).Count
        $office.MacroPolicyPresent = ($anyApp -gt 0)
        $out.Office = $office
    } catch { _err 'Office' $_.Exception.Message }

    # ---------------- Browsers and Java
    try {
        function _browser { param($PolicyKey, $ExePaths)
            $ver = $null; foreach ($p in $ExePaths) { if (Test-Path $p) { $ver = (Get-Item $p).VersionInfo.ProductVersion; break } }
            $polCount = 0; $force = @(); $extra = [ordered]@{}
            if (Test-Path $PolicyKey) {
                $polCount = @((Get-Item $PolicyKey).Property).Count
                if (Test-Path "$PolicyKey\ExtensionInstallForcelist") { $force = @((Get-ItemProperty "$PolicyKey\ExtensionInstallForcelist").PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Value }) }
                foreach ($n in 'DeveloperToolsAvailability', 'PasswordManagerEnabled', 'SmartScreenEnabled', 'SafeBrowsingProtectionLevel', 'InternetExplorerIntegrationLevel', 'DefaultJavaScriptJitSetting', 'SSLVersionMin', 'BrowserSignin', 'AutofillCreditCardEnabled') { $v = _reg $PolicyKey $n; if ($null -ne $v) { $extra[$n] = $v } }
            }
            return [ordered]@{ Installed = [bool]$ver; Version = $ver; PolicyCount = $polCount; ForceInstalledExtensions = $force; KeySettings = $extra }
        }
        $b = [ordered]@{}
        $b.Edge = _browser 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' @("$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
        $b.Chrome = _browser 'HKLM:\SOFTWARE\Policies\Google\Chrome' @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe")
        $ffExe = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "$env:ProgramFiles (x86)\Mozilla Firefox\firefox.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
        $b.Firefox = [ordered]@{ Installed = [bool]$ffExe; Version = $(if ($ffExe) { (Get-Item $ffExe).VersionInfo.ProductVersion } else { $null }); PoliciesPresent = ((Test-Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox') -or ($ffExe -and (Test-Path (Join-Path (Split-Path $ffExe) 'distribution\policies.json')))) }
        $java = @()
        foreach ($k in 'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment', 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment', 'HKLM:\SOFTWARE\JavaSoft\JDK', 'HKLM:\SOFTWARE\JavaSoft\Java Development Kit') { if (Test-Path $k) { $java += @(Get-ChildItem $k | ForEach-Object { $_.PSChildName }) } }
        $b.JavaRuntimes = @($java | Select-Object -Unique)
        $out.Browsers = $b
    } catch { _err 'Browsers' $_.Exception.Message }

    # ---------------- Application control (AppLocker / WDAC / Airlock)
    try {
        $ac = [ordered]@{}
        try {
            [xml]$pol = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            $cols = [ordered]@{}
            foreach ($c in $pol.AppLockerPolicy.RuleCollection) { $cols[$c.Type] = [ordered]@{ Enforcement = $c.EnforcementMode; Rules = @($c.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count } }
            $ac.AppLocker = [ordered]@{ Present = ($cols.Count -gt 0); Collections = $cols; AppIDSvcRunning = ((_svc 'AppIDSvc').Status -eq 'Running') }
        } catch { $ac.AppLocker = [ordered]@{ Present = $false; Error = $_.Exception.Message } }
        $wd = [ordered]@{ ActivePolicies = @() }
        if ($out.Hardening.WDAC) { $wd.CodeIntegrityPolicyEnforcementStatus = $out.Hardening.WDAC.CodeIntegrityPolicyEnforcementStatus; $wd.UsermodeCodeIntegrityPolicyEnforcementStatus = $out.Hardening.WDAC.UsermodeCodeIntegrityPolicyEnforcementStatus; $wd.Meaning = @{0 = 'Off'; 1 = 'Audit'; 2 = 'Enforced' }[[int]$wd.UsermodeCodeIntegrityPolicyEnforcementStatus] }
        try { if (Get-Command citool.exe -ErrorAction SilentlyContinue) { $ct = citool --list-policies --json 2>$null | ConvertFrom-Json; $wd.ActivePolicies = @($ct.Policies | ForEach-Object { [pscustomobject]@{ Name = $_.FriendlyName; Enforced = $_.IsEnforced; Id = $_.PolicyID; System = $_.IsSystemPolicy } }) } } catch { }
        $wd.SIPolicyFilePresent = (Test-Path "$env:windir\System32\CodeIntegrity\SIPolicy.p7b") -or ((Test-Path "$env:windir\System32\CodeIntegrity\CiPolicies\Active") -and @(Get-ChildItem "$env:windir\System32\CodeIntegrity\CiPolicies\Active" -ErrorAction SilentlyContinue).Count -gt 0)
        $ac.WDAC = $wd
        $ac.ThirdParty = @($out.Agents.AppControl)
        $out.AppControl = $ac
    } catch { _err 'AppControl' $_.Exception.Message }

    # ---------------- Local accounts
    try {
        $members = @()
        try { $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Type = "$($_.ObjectClass)"; Source = "$($_.PrincipalSource)" } }) }
        catch { $raw = net localgroup administrators 2>$null; $members = @($raw | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch '^The command completed' -and $_ -notmatch '^-+$' } | ForEach-Object { [pscustomobject]@{ Name = $_.Trim(); Type = 'Unknown'; Source = 'Unknown' } }) }
        $builtin = $null; $guest = $null; $locals = @()
        try { $lu = Get-LocalUser -ErrorAction Stop; $builtin = $lu | Where-Object { $_.SID -like '*-500' }; $guest = $lu | Where-Object { $_.SID -like '*-501' }; $locals = @($lu | Where-Object { $_.Enabled -and $_.SID -notlike '*-500' -and $_.SID -notlike '*-501' -and $_.SID -notlike '*-503' -and $_.SID -notlike '*-504' } | Select-Object -ExpandProperty Name) } catch { }
        $expected = @('Administrator', 'Domain Admins', 'Enterprise Admins')
        $nonStd = @($members | Where-Object { $n = ($_.Name -split '\\')[-1]; ($expected -notcontains $n) -and ($_.Name -notmatch '\\Domain Admins$|\\Enterprise Admins$|-500$') })
        $out.LocalAccounts = [ordered]@{
            Administrators = $members; AdminCount = $members.Count; NonStandardAdmins = @($nonStd | ForEach-Object { $_.Name }); NonStandardAdminCount = $nonStd.Count
            BuiltinAdminEnabled = $(if ($builtin) { $builtin.Enabled } else { $null }); BuiltinAdminName = $(if ($builtin) { $builtin.Name } else { $null }); BuiltinAdminPasswordAgeDays = $(if ($builtin -and $builtin.PasswordLastSet) { [int]((Get-Date) - $builtin.PasswordLastSet).TotalDays } else { $null })
            GuestEnabled = $(if ($guest) { $guest.Enabled } else { $null }); OtherEnabledLocalUsers = $locals
        }
    } catch { _err 'LocalAccounts' $_.Exception.Message }

    # ---------------- Encryption
    try {
        $enc2 = [ordered]@{ BitLockerAvailable = $false }
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $enc2.BitLockerAvailable = $true
            $vols = Get-BitLockerVolume -ErrorAction Stop
            $enc2.Volumes = @($vols | ForEach-Object { [pscustomobject]@{ Mount = $_.MountPoint; Type = "$($_.VolumeType)"; ProtectionStatus = "$($_.ProtectionStatus)"; VolumeStatus = "$($_.VolumeStatus)"; EncryptionMethod = "$($_.EncryptionMethod)"; EncryptionPercentage = $_.EncryptionPercentage; KeyProtectors = @($_.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" }) } })
            $osv = $vols | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
            $enc2.OSVolumeProtected = $(if ($osv) { "$($osv.ProtectionStatus)" -eq 'On' } else { $null })
            $enc2.OSVolumeHasRecoveryPassword = $(if ($osv) { (@($osv.KeyProtector | Where-Object { "$($_.KeyProtectorType)" -eq 'RecoveryPassword' }).Count -gt 0) } else { $null })
        }
        $enc2.RecoveryKeyEscrow = 'Not determinable locally - see Entra/AD BitLocker key evidence'
        $out.Encryption = $enc2
    } catch { _err 'Encryption' $_.Exception.Message }

    # ---------------- Network / time / listeners
    try {
        $adapters = @()
        try { $adapters = @(Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | ForEach-Object { [pscustomobject]@{ Name = $_.InterfaceAlias; IPv4 = @($_.IPv4Address.IPAddress); Gateway = $_.IPv4DefaultGateway.NextHop; DNS = @($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) } }) } catch { }
        $nb = @()
        try { $nb = @(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object { [pscustomobject]@{ Adapter = $_.Description; TcpipNetbiosOptions = $_.TcpipNetbiosOptions; DHCP = $_.DHCPEnabled } }) } catch { }
        $listen = @()
        try {
            $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
            $listen = @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' } | Group-Object LocalPort | ForEach-Object { [pscustomobject]@{ Port = [int]$_.Name; Process = ($_.Group | ForEach-Object { $procs[[int]$_.OwningProcess] } | Select-Object -Unique) -join ',' } } | Sort-Object Port)
        } catch { }
        $risky = @($listen | Where-Object { $_.Port -in 21, 23, 69, 135, 139, 445, 1433, 1434, 3306, 3389, 5900, 5985, 5986, 8080, 8443, 9200, 27017 })
        $timeSrc = $null; $timeType = $null
        try { $timeSrc = (w32tm /query /source 2>$null | Select-Object -First 1); $timeType = (w32tm /query /configuration 2>$null | Select-String '^\s*Type:\s*(\S+)' | ForEach-Object { $_.Matches.Groups[1].Value } | Select-Object -First 1) } catch { }
        $out.Network = [ordered]@{ Adapters = $adapters; NetBIOS = $nb; ListeningPorts = @($listen | Select-Object -First 60); RiskyListeners = $risky; TimeSource = $timeSrc; TimeSyncType = $timeType; TimeSourceIsLocalClock = ($timeSrc -match 'Local CMOS Clock|Free-running') ; WinRMRunning = ((_svc 'WinRM').Status -eq 'Running') }
    } catch { _err 'Network' $_.Exception.Message }

    # ---------------- Storage and shares
    try {
        $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [pscustomobject]@{ Drive = $_.DeviceID; SizeGB = [math]::Round($_.Size / 1GB, 1); FreeGB = [math]::Round($_.FreeSpace / 1GB, 1); FreePct = $(if ($_.Size) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { $null }) } })
        $shares = @()
        try {
            $broadNames = 'Everyone', 'Authenticated Users', 'Domain Users', 'Users', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'
            foreach ($s in (Get-SmbShare | Where-Object { $_.Name -notmatch '^\w\$$|^ADMIN\$$|^IPC\$$|^print\$$|^NETLOGON$|^SYSVOL$' })) {
                $acc = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Account = $_.AccountName; Right = "$($_.AccessRight)"; Type = "$($_.AccessControlType)" } })
                $broad = @($acc | Where-Object { $_.Type -eq 'Allow' -and $_.Right -in 'Change', 'Full' -and (($broadNames | ForEach-Object { $_.ToLower() }) -contains $_.Account.ToLower() -or $_.Account -match 'Everyone|Authenticated Users|Domain Users') }).Count -gt 0
                $shares += [pscustomobject]@{ Name = $s.Name; Path = $s.Path; Description = $s.Description; Access = $acc; BroadWriteAccess = $broad }
            }
        } catch { }
        if ($out.Roles) { $out.Roles.HasFileShares = ($shares.Count -gt 0) }
        $out.Storage = [ordered]@{ Volumes = $vols; LowSpaceVolumes = @($vols | Where-Object { $_.FreePct -ne $null -and $_.FreePct -lt 15 } | ForEach-Object { "$($_.Drive) $($_.FreePct)%" }); Shares = $shares; BroadWriteShares = @($shares | Where-Object { $_.BroadWriteAccess } | ForEach-Object { $_.Name }) }
    } catch { _err 'Storage' $_.Exception.Message }

    # ---------------- Certificates (LocalMachine\My)
    try {
        $certs = @(Get-ChildItem Cert:\LocalMachine\My | ForEach-Object { [pscustomobject]@{ Subject = $_.Subject; Issuer = $_.Issuer; NotAfter = $_.NotAfter; DaysLeft = [int]($_.NotAfter - (Get-Date)).TotalDays; HasPrivateKey = $_.HasPrivateKey; Thumbprint = $_.Thumbprint; SelfSigned = ($_.Subject -eq $_.Issuer) } })
        $out.Certificates = [ordered]@{ Count = $certs.Count; ExpiringOrExpired = @($certs | Where-Object { $_.DaysLeft -lt 60 -and $_.HasPrivateKey } | Sort-Object DaysLeft); All = @($certs | Select-Object Subject, NotAfter, DaysLeft, SelfSigned) }
    } catch { _err 'Certificates' $_.Exception.Message }

    # ---------------- Installed software + watchlist
    try {
        $sw2 = [ordered]@{ Count = 0; Watchlist = @(); RemoteTools = @(); DotNetRelease = (_reg 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' 'Release'); DotNetVersion = (_reg 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' 'Version') }
        if (-not $SkipInstalledSoftware) {
            $apps2 = @()
            foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
                $apps2 += @(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate)
            }
            $apps2 = @($apps2 | Sort-Object DisplayName -Unique)
            $sw2.Count = $apps2.Count
            function _v { param($s) try { return [version]($s -replace '[^\d\.].*$', '') } catch { return $null } }
            $watch = @(
                @{ Match = '^Java\b|^Java \d|Java\(TM\)|OpenJDK|Adoptium|Temurin|Zulu'; Note = 'Java runtime present - confirm business need and patch cadence (E8 PA)'; Flag = 'Info' },
                @{ Match = 'Adobe Flash'; Note = 'Adobe Flash Player - end of life, must be removed (E8 PA ML1)'; Flag = 'Attention' },
                @{ Match = '^7-Zip'; MinVer = '23.1'; Note = '7-Zip below 23.01 (CVE-2023-31102)'; Flag = 'Attention' },
                @{ Match = '^WinRAR'; MinVer = '6.23'; Note = 'WinRAR below 6.23 (CVE-2023-38831, exploited)'; Flag = 'Attention' },
                @{ Match = '^PuTTY'; MinVer = '0.81'; Note = 'PuTTY below 0.81 (CVE-2024-31497)'; Flag = 'Attention' },
                @{ Match = 'Adobe Acrobat|Adobe Reader'; Note = 'PDF software - confirm current track and hardening (E8 UAH)'; Flag = 'Info' },
                @{ Match = 'Microsoft Office (Professional|Standard|Home).*(2010|2013|2016|2019)'; Note = 'Perpetual Office 2010-2019 - out of support (2016/2019 since 14 Oct 2025)'; Flag = 'Attention' },
                @{ Match = 'Microsoft Visual C\+\+ 2005|Microsoft Visual C\+\+ 2008'; Note = 'Legacy VC++ runtimes'; Flag = 'Info' },
                @{ Match = 'Silverlight'; Note = 'Microsoft Silverlight - end of life Oct 2021'; Flag = 'Attention' },
                @{ Match = 'QuickTime'; Note = 'Apple QuickTime for Windows - unsupported'; Flag = 'Attention' },
                @{ Match = '^VMware Tools'; Note = 'VMware Tools version (compare with host)'; Flag = 'Info' },
                @{ Match = 'TeamViewer|AnyDesk|ScreenConnect|Splashtop|LogMeIn|RustDesk|GoTo|Chrome Remote Desktop|UltraVNC|TightVNC|RealVNC|Ammyy|Supremo|Zoho Assist|Remote Utilities|DWService'; Note = 'Remote access tool - approved vendor path? (SEC-12; block via app control if unsanctioned)'; Flag = 'Attention'; Remote = $true },
                @{ Match = 'Wireshark|Nmap|Npcap'; Note = 'Network analysis tool on host'; Flag = 'Info' },
                @{ Match = 'Dropbox|Google Drive|Box\b|MEGAsync|pCloud'; Note = 'Third-party sync client - sanctioned? (BDR-07 / AZ-08)'; Flag = 'Info' },
                @{ Match = 'Veeam'; Note = 'Veeam component'; Flag = 'Info' },
                @{ Match = 'Microsoft SQL Server \d{4}'; Note = 'SQL Server component (see Roles.SqlInstances for engine version)'; Flag = 'Info' }
            )
            $wl = New-Object System.Collections.ArrayList; $remote = New-Object System.Collections.ArrayList
            foreach ($a in $apps2) {
                foreach ($w in $watch) {
                    if ($a.DisplayName -match $w.Match) {
                        $flag = $w.Flag; $note = $w.Note
                        if ($w.MinVer) { $v = _v $a.DisplayVersion; if ($v -and $v -ge [version]$w.MinVer) { $flag = 'OK'; $note = "$($a.DisplayName) at or above $($w.MinVer)" } elseif (-not $v) { $flag = 'Info'; $note = "$note (version unparsable)" } }
                        $null = $wl.Add([pscustomobject]@{ Name = $a.DisplayName; Version = $a.DisplayVersion; Publisher = $a.Publisher; Flag = $flag; Note = $note })
                        if ($w.Remote) { $null = $remote.Add($a.DisplayName) }
                        break
                    }
                }
            }
            $sw2.Watchlist = @($wl); $sw2.RemoteTools = @($remote | Select-Object -Unique)
            $sw2.Browsers = @($apps2 | Where-Object { $_.DisplayName -match '^Google Chrome$|^Microsoft Edge$|^Mozilla Firefox' } | ForEach-Object { "{0} {1}" -f $_.DisplayName, $_.DisplayVersion })
            $sw2.All = @($apps2 | Select-Object DisplayName, DisplayVersion, Publisher)
        }
        $out.Software = $sw2
    } catch { _err 'Software' $_.Exception.Message }

    # ---------------- Events (light)
    try {
        $ev = [ordered]@{}
        try { $ev.FailedLogons24h = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 500 -ErrorAction Stop).Count } catch { $ev.FailedLogons24h = 0 }
        try { $ev.SecurityLogCleared90d = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = (Get-Date).AddDays(-90) } -MaxEvents 10 -ErrorAction Stop).Count } catch { $ev.SecurityLogCleared90d = 0 }
        try { $ev.UnexpectedShutdowns30d = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6008, 41; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 50 -ErrorAction Stop).Count } catch { $ev.UnexpectedShutdowns30d = 0 }
        $out.Events = $ev
    } catch { _err 'Events' $_.Exception.Message }

    $out.Errors = @($errors)
    $out.Meta.ElapsedSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    return [pscustomobject]$out
}

# --- support helpers duplicated here so the agent has no dependency on lib\CER.Common.ps1 ---
if (-not (Get-Command Get-CERWindowsSupport -ErrorAction SilentlyContinue)) {
function Get-CERWindowsSupport {
    param([string]$Caption, [string]$Version, [int]$ProductType = 1, [string]$EditionId)
    $build = 0; if ($Version -match '(\d+)\.(\d+)\.(\d+)') { $build = [int]$Matches[3] }
    $major = if ($Version -match '^(\d+)\.(\d+)') { "$($Matches[1]).$($Matches[2])" } else { '' }
    $r = [ordered]@{ Family = ''; Supported = $true; EndOfSupport = ''; Note = '' }
    if ($ProductType -eq 1) {
        if ($major -eq '10.0' -and $build -ge 22000) { $r.Family = 'Windows 11' }
        elseif ($major -eq '10.0') { if ($EditionId -match 'EnterpriseS') { $r.Family = 'Windows 10 LTSC' } else { $r.Family = 'Windows 10'; $r.Supported = $false; $r.EndOfSupport = '14 Oct 2025'; $r.Note = 'Out of support unless enrolled in ESU' } }
        elseif ($major -eq '6.3') { $r.Family = 'Windows 8.1'; $r.Supported = $false; $r.EndOfSupport = '10 Jan 2023' }
        elseif ($major -eq '6.1') { $r.Family = 'Windows 7'; $r.Supported = $false; $r.EndOfSupport = '14 Jan 2020' }
        else { $r.Family = $Caption }
    } else {
        if ($major -eq '10.0' -and $build -ge 26100) { $r.Family = 'Windows Server 2025' }
        elseif ($major -eq '10.0' -and $build -ge 20348) { $r.Family = 'Windows Server 2022'; $r.Note = 'Mainstream ends 13 Oct 2026' }
        elseif ($major -eq '10.0' -and $build -ge 17763) { $r.Family = 'Windows Server 2019'; $r.Note = 'Extended support to 9 Jan 2029' }
        elseif ($major -eq '10.0' -and $build -ge 14393) { $r.Family = 'Windows Server 2016'; $r.EndOfSupport = '12 Jan 2027'; $r.Note = 'Plan migration now' }
        elseif ($major -eq '6.3') { $r.Family = 'Windows Server 2012 R2'; $r.Supported = $false; $r.EndOfSupport = '10 Oct 2023 (ESU year 3 ends 13 Oct 2026)' }
        elseif ($major -eq '6.2') { $r.Family = 'Windows Server 2012'; $r.Supported = $false; $r.EndOfSupport = '10 Oct 2023 (ESU year 3 ends 13 Oct 2026)' }
        elseif ($major -eq '6.1') { $r.Family = 'Windows Server 2008 R2'; $r.Supported = $false; $r.EndOfSupport = '14 Jan 2020' }
        elseif ($major -eq '6.0') { $r.Family = 'Windows Server 2008'; $r.Supported = $false; $r.EndOfSupport = '14 Jan 2020' }
        else { $r.Family = $Caption }
    }
    return [pscustomobject]$r
}
function Get-CERSqlSupport {
    param([string]$Version)
    $maj = 0; if ($Version -match '^(\d+)\.') { $maj = [int]$Matches[1] }
    switch ($maj) {
        16 { return @{ Name = 'SQL Server 2022'; Supported = $true; Note = 'Mainstream to 11 Jan 2028' } }
        15 { return @{ Name = 'SQL Server 2019'; Supported = $true; Note = 'Extended support to 8 Jan 2030' } }
        14 { return @{ Name = 'SQL Server 2017'; Supported = $true; Note = 'Extended support to 12 Oct 2027' } }
        13 { return @{ Name = 'SQL Server 2016'; Supported = $false; Note = 'Out of support since 14 Jul 2026 (ESU available)' } }
        12 { return @{ Name = 'SQL Server 2014'; Supported = $false; Note = 'Out of support since 9 Jul 2024 (ESU available)' } }
        11 { return @{ Name = 'SQL Server 2012'; Supported = $false; Note = 'Out of support since 12 Jul 2022' } }
        default { return @{ Name = "SQL Server (version $Version)"; Supported = $true; Note = 'Verify against Microsoft Lifecycle' } }
    }
}
$script:CERAsrRules = @{
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'; '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from injecting code into other processes'; '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'; '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'; '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'; '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'; 'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'; '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless they meet prevalence/age/trusted criteria'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'; '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'; '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode (preview)'; 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools (preview)'
}
function Get-CERAsrRuleName { param([string]$Id) $n = $script:CERAsrRules[$Id.ToLower()]; if ($n) { return $n } return $Id }
}
#endregion HOSTSTATE

# ---- ENTRYPOINT (not executed when the Servers collector extracts the HOSTSTATE region) ----
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.MyCommand.Path) {
    $state = Get-CERHostState -IncludeWindowsUpdateSearch:$IncludeWindowsUpdateSearch -SkipInstalledSoftware:$SkipInstalledSoftware
    $json = $state | ConvertTo-Json -Depth 9
    $file = "{0}.cer-host.json" -f $env:COMPUTERNAME
    foreach ($dest in @($OutputPath, $OutputShare)) {
        if ($dest) {
            try { if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }; $json | Set-Content -Path (Join-Path $dest $file) -Encoding UTF8 }
            catch { Write-Warning ("Could not write to {0}: {1}" -f $dest, $_.Exception.Message) }
        }
    }
    if (-not $Quiet) { $json }
}
