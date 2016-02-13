#Check for admin privileges

param([switch]$Elevated)

function Test-Admin {
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated)
    {
        # tried to elevate, did not work, aborting
    }
    else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
}

exit
}

'running with full privileges'

# If key doesn't exist add key and add name and value to key
function AddRegisterKeys ($registerKeys)
{
    forEach ($registerKey in $registerKeys)
    {
        if ($registerKey.Key -and $registerKey.Name -and $registerKey.Value)
        {
            $key = $registerKey.Key
            $name = $registerKey.Name
            $value = $registerKey.Value
            If  ( -Not ( Test-Path "Registry::$key")){New-Item -Path "Registry::$key" -ItemType RegistryKey -Force}
            Set-ItemProperty -path "Registry::$key" -Name $name -Value $value
        }
    }
}

# Remove Telemetry and Data Collection
$registerKeys = @(`
@{Key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0}
@{Key= "HKLM\SOFTWARE\Policies\Microsoft\MRT"; Name = "DontOfferThroughWUAU"; Value = 1}
@{Key= "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Value = 0}
@{Key= "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Value = 0}
@{Key= "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableUAR"; Value = 1}
@{Key= "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0}
@{Key= "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"; Name = "PreventDeviceMetadataFromNetwork"; Value = 1}
@{Key= "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Value = 0}
)


# Show hidden files / system tweaks
$registerKeys += @(`
@{Key= "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"; Name = "NoPreviousVersionsPage"; Value = 1}
@{Key= "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer"; Name = "EnableAutoTray"; Value = 0}
@{Key= "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "HideFileExt"; Value = 0}
@{Key= "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Hidden"; Value = 1}
@{Key= "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowSuperHidden"; Value = 1}
@{Key= "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name = "EnablePrefetcher"; Value = 0}
@{Key= "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name = "EnableSuperfetch"; Value = 0}
)

# Add take ownership to context menu
$registerKeys += @(`
@{Key= "HKEY_CLASSES_ROOT\``*\shell\runas"; Name = "(Default)"; Value = "Take Ownership"}
@{Key= "HKEY_CLASSES_ROOT\``*\shell\runas"; Name = "HasLUAShield"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\``*\shell\runas"; Name = "NoWorkingDirectory"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\``*\shell\runas\command"; Name = "(Default)"; Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'}
@{Key= "HKEY_CLASSES_ROOT\``*\shell\runas\command"; Name = "IsolatedCommand"; Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'}
@{Key= "HKEY_CLASSES_ROOT\Directory\shell\runas"; Name = "(Default)"; Value = "Take Ownership"}
@{Key= "HKEY_CLASSES_ROOT\Directory\shell\runas"; Name = "HasLUAShield"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\Directory\shell\runas\command"; Name = "NoWorkingDirectory"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\Directory\shell\runas"; Name = "(Default)"; Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'}
@{Key= "HKEY_CLASSES_ROOT\Directory\shell\runas"; Name = "IsolatedCommand"; Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'}
@{Key= "HKEY_CLASSES_ROOT\dllfile\shell\runas"; Name = "(Default)"; Value = "Take Ownership"}
@{Key= "HKEY_CLASSES_ROOT\dllfile\shell\runas"; Name = "HasLUAShield"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\dllfile\shell\runas"; Name = "NoWorkingDirectory"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\dllfile\shell\runas\command"; Name = "(Default)"; Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'}
@{Key= "HKEY_CLASSES_ROOT\dllfile\shell\runas\command"; Name = "IsolatedCommand"; Value = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F /c /l && pause'}
@{Key= "HKEY_CLASSES_ROOT\Drive\shell\runas"; Name = "(Default)"; Value = "Take Ownership"}
@{Key= "HKEY_CLASSES_ROOT\Drive\shell\runas"; Name = "HasLUAShield"; Value = ""},`
@{Key= "HKEY_CLASSES_ROOT\Drive\shell\runas"; Name = "NoWorkingDirectory"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\Drive\shell\runas\command"; Name = "(Default)"; Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'}
@{Key= "HKEY_CLASSES_ROOT\Drive\shell\runas\command"; Name = "IsolatedCommand"; Value = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t /c /l /q && pause'}
@{Key= "HKEY_CLASSES_ROOT\exefile\shell\runas"; Name = "HasLUAShield"; Value = ""}
@{Key= "HKEY_CLASSES_ROOT\exefile\shell\runas\command"; Name = "(Default)"; Value = '"%1" %*'}
@{Key= "HKEY_CLASSES_ROOT\exefile\shell\runas\command"; Name = "IsolatedCommand"; Value = '"%1" %*'}
)

# Disable automatic windows update - notify if updates are available
$registerKeys += @(`
@{Key= "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "AUOptions"; Value = 2}
@{Key= "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; Value = 0}
@{Key= "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoRebootWithLoggedOnUsers"; Value = 1}
@{Key= "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "ScheduledInstallDay"; Value = 0}
@{Key= "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "ScheduledInstallTime"; Value = 3}
)


AddRegisterKeys -registerKeys $registerKeys

# Disable Telemetry and Data Collection hosts by adding them to the hosts file
function AddHosts($newHosts)
{
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hosts = get-content $hostsPath

    $hosts += ""

    Foreach ($newHost in $newHosts)
    {
        $exists = $FALSE
        Foreach ($_ in $hosts)
        {
            if ($_ -match $newHost)
            {
            $exists = $TRUE
            }
        }
        if ($exists -eq $FALSE)
        {
            $hosts += "$($newHost)"
        }
    }

    $hosts | Out-File $hostsPath
}

$hosts = @(`
"# Windows 10 Telemetry and Data Collection hosts"
"0.0.0.0 vortex.data.microsoft.com"
"0.0.0.0 vortex-win.data.microsoft.com"
"0.0.0.0 telecommand.telemetry.microsoft.com"
"0.0.0.0 vortex.data.microsoft.com"
"0.0.0.0 vortex-win.data.microsoft.com"
"0.0.0.0 telecommand.telemetry.microsoft.com"
"0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net"
"0.0.0.0 oca.telemetry.microsoft.com"
"0.0.0.0 oca.telemetry.microsoft.com.nsatc.net"
"0.0.0.0 sqm.telemetry.microsoft.com"
"0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net"
"0.0.0.0 watson.telemetry.microsoft.com"
"0.0.0.0 watson.telemetry.microsoft.com.nsatc.net"
"0.0.0.0 redir.metaservices.microsoft.com"
"0.0.0.0 choice.microsoft.com"
"0.0.0.0 choice.microsoft.com.nsatc.net"
"0.0.0.0 df.telemetry.microsoft.com"
"0.0.0.0 reports.wes.df.telemetry.microsoft.com"
"0.0.0.0 wes.df.telemetry.microsoft.com"
"0.0.0.0 services.wes.df.telemetry.microsoft.com"
"0.0.0.0 sqm.df.telemetry.microsoft.com"
"0.0.0.0 telemetry.microsoft.com"
"0.0.0.0 watson.ppe.telemetry.microsoft.com"
"0.0.0.0 telemetry.appex.bing.net"
"0.0.0.0 telemetry.urs.microsoft.com"
"0.0.0.0 telemetry.appex.bing.net:443"
"0.0.0.0 settings-sandbox.data.microsoft.com"
"0.0.0.0 vortex-sandbox.data.microsoft.com"
"0.0.0.0 survey.watson.microsoft.com"
"0.0.0.0 watson.live.com"
"0.0.0.0 watson.microsoft.com"
"0.0.0.0 statsfe2.ws.microsoft.com"
"0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com"
"0.0.0.0 compatexchange.cloudapp.net"
"0.0.0.0 cs1.wpc.v0cdn.net"
"0.0.0.0 a-0001.a-msedge.net"
"0.0.0.0 statsfe2.update.microsoft.com.akadns.net"
"0.0.0.0 sls.update.microsoft.com.akadns.net"
"0.0.0.0 fe2.update.microsoft.com.akadns.net"
"0.0.0.0 65.55.108.23"
"0.0.0.0 65.39.117.230"
"0.0.0.0 23.218.212.69"
"0.0.0.0 134.170.30.202"
"0.0.0.0 137.116.81.24"
"0.0.0.0 diagnostics.support.microsoft.com"
"0.0.0.0 corp.sts.microsoft.com"
"0.0.0.0 statsfe1.ws.microsoft.com"
"0.0.0.0 pre.footprintpredict.com"
"0.0.0.0 204.79.197.200"
"0.0.0.0 23.218.212.69"
"0.0.0.0 i1.services.social.microsoft.com"
"0.0.0.0 i1.services.social.microsoft.com.nsatc.net"
"0.0.0.0 feedback.windows.com"
"0.0.0.0 feedback.microsoft-hohm.com"
"0.0.0.0 feedback.search.microsoft.com"
"0.0.0.0 64.4.54.117"
"0.0.0.0 8.254.208.254"
)


# Disable skype adds hosts
$hosts += @(
"# Skype adds hosts"
"127.0.0.1 http://rad.msn.com"
"127.0.0.1 http://live.rads.msn.com"
"127.0.0.1 http://ads1.msn.com"
"127.0.0.1 http://static.2mdn.net"
"127.0.0.1 http://g.msn.com"
"127.0.0.1 http://a.ads2.msads.net"
"127.0.0.1 http://b.ads2.msads.net"
"127.0.0.1 http://ac3.msn.com"
"127.0.0.1 http://apps.skype.com"
)

AddHosts -newHost $hosts

# Remove Universal apps
function RemoveApps ($apps)
{
    forEach ($app in $apps)
    {
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage
    }
}

$apps = @(`
"Microsoft.3DBuilder"
"Microsoft.Getstarted"
"Microsoft.MicrosoftOfficeHub"
"Microsoft.MicrosoftSolitaireCollection"
"Microsoft.SkypeApp"
"Microsoft.WindowsMaps"
"Microsoft.BingWeather"
"Microsoft.Office.OneNote"
"Microsoft.ZuneMusic"
"Microsoft.ZuneVideo"
"Microsoft.BingSports"
"Microsoft.BingNews"
"Microsoft.WindowsPhone"
"Microsoft.BingFinance"
"microsoft.windowscommunicationsapps"
"Microsoft.WindowsSoundRecorder"
"Microsoft.Getstarted"
"Microsoft.Windows.Photos"
"Microsoft.WindowsCamera"
"Microsoft.WindowsAlarms"
"Microsoft.WindowsCalculator"
"Microsoft.WindowsStore"
"Microsoft.People"
"Microsoft.XboxApp"
)

RemoveApps -apps $apps


# Disable services
function DisableService ($services)
{
    forEach ($service in $services)
    {
        Set-Service $service -StartupType Disabled
        Stop-Service $service
    }
}

$services = @(
"AJRouter"
"AppHostSvc"
"ALG"
"bthserv"
"CscService"
"DiagTrack"
"diagnosticshub.standardcollector.service"
"dmwappushservice"
"EntAppSvc"
"fsvc"
"hkmsvc"
"icssvc"
"RemoteRegistry"
"RetailDemo"
"TrkWks"
"WMPNetworkSvc"
"AJRouter"
"bthserv"
"PeerDistSvc"
"CertPropSvc"
"DcpSvc"
"Fax"
"vmickvpexchange"
"vmicguestinterface"
"vmicshutdown"
"vmicheartbeat"
"vmicrdv"
"vmictimesync"
"vmicvss"
"IEEtwCollectorService"
"iphlpsvc"
"MSiSCSI"
"MapsBroker"
"NfsClnt"
"Netlogon"
"CscService"
"RpcLocator"
"SharedAccess"
"SensrSvc"
"SensorDataService"
"SensorService"
"ScDeviceEnum"
"SCPolicySvc"
"SmsRouter"
"SNMPTRAP"
"StorSvc"
"TabletInputService"
"WbioSrvc"
"wcncsvc"
"WinRM"
"WbioSrvc"
"Wms"
"WmsRepair"
"workfolderssvc"
"XblAuthManager"
"XblGameSave"
"XboxNetApiSvc"
)

DisableService -services $services

# Disable scheduled tasks
function DisableScheduledTasks ($tasks)
{
    forEach ($task in $tasks)
    {
        Disable-ScheduledTask $task
    }
}

$tasks = @(
"Microsoft\Windows\AppID\SmartScreenSpecific"
"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
"Microsoft\Windows\Application Experience\ProgramDataUpdater"
"Microsoft\Windows\Application Experience\StartupAppTask"
"Microsoft\Windows\Autochk\Proxy"
"Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
"Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
"Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
"Microsoft\Windows\DiskFootprint\Diagnostics"
"Microsoft\Windows\FileHistory\File History (maintenance mode)"
"Microsoft\Windows\Maintenance\WinSAT"
"Microsoft\Windows\NetTrace\GatherNetworkInfo"
"Microsoft\Windows\PI\Sqm-Tasks"
"Microsoft\Windows\Windows Error Reporting\QueueReporting"
"Microsoft\Windows\WindowsUpdate\Automatic App Update"
)

DisableScheduledTasks -tasks $tasks
