Write-Host "[+] Disable Windows Defender (as $(whoami))"

Set-ItemProperty -Path "HKCU:\Software\Sysinternals\PsExec" -Name "EulaAccepted" -Value 1 -Force -ErrorAction SilentlyContinue

if(-Not $($(whoami) -eq "nt authority\system")) {
    $IsSystem = $false

    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Host "    [i] Elevate to Administrator"
        $CommandLine = "-ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }

    $psexec_path = $(Get-Command PsExec -ErrorAction 'ignore').Source 
    if($psexec_path) {
        Write-Host "    [i] Elevate to SYSTEM"
        $CommandLine = " /accepteula -i -s powershell.exe -ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments 
        Start-Process -WindowStyle Hidden -FilePath $psexec_path -ArgumentList $CommandLine
        exit
    } else {
        Write-Host "    [i] PsExec not found, will continue as Administrator"
    }

} else {
    $IsSystem = $true
}

Write-Host "    [+] Add exclusions"


67..90|foreach-object{
    $drive = [char]$_
    Add-MpPreference -ExclusionPath "$($drive):\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "$($drive):\*" -ErrorAction SilentlyContinue
}

Write-Host "    [+] Disable scanning engines (Set-MpPreference)"

Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue

Write-Host "    [+] Set default actions to Allow (Set-MpPreference)"

Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue

Write-Host "    [+] Disable services"

$need_reboot = $false

$svc_list = @("WdNisSvc", "WinDefend", "Sense")
foreach($svc in $svc_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
            Write-Host "        [i] Service $svc already disabled"
        } else {
            Write-Host "        [i] Disable service $svc (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Service $svc already deleted"
    }
}

Write-Host "    [+] Disable drivers"


$drv_list = @("WdnisDrv", "wdfilter", "wdboot")
foreach($drv in $drv_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
            Write-Host "        [i] Driver $drv already disabled"
        } else {
            Write-Host "        [i] Disable driver $drv (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Driver $drv already deleted"
    }
}

if($(GET-Service -Name WinDefend).Status -eq "Running") {   
    Write-Host "    [+] WinDefend Service still running (reboot required)"
    $need_reboot = $true
} else {
    Write-Host "    [+] WinDefend Service not running"
}



$link_reboot = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\disable-defender.lnk"
Remove-Item -Force "$link_reboot" -ErrorAction 'ignore' 

if($need_reboot) {
    Write-Host "    [+] This script will be started again after reboot." -BackgroundColor DarkRed -ForegroundColor White
    
    $powershell_path = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"'
    $cmdargs = "-ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    
    $res = New-Item $(Split-Path -Path $link_reboot -Parent) -ItemType Directory -Force
    $WshShell = New-Object -comObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($link_reboot)
    $shortcut.TargetPath = $powershell_path
    $shortcut.Arguments = $cmdargs
    $shortcut.WorkingDirectory = "$(Split-Path -Path $PSScriptRoot -Parent)"
    $shortcut.Save()

} else {


    if($IsSystem) {


        Write-Host "    [+] Disable all functionnalities with registry keys (SYSTEM privilege)"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SpyNetReporting -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SubmitSamplesConsent -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -Value 4

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1

    } else {
        Write-Host "    [W] (Optional) Cannot configure registry (not SYSTEM)"
    }


    if($MyInvocation.UnboundArguments -And $($MyInvocation.UnboundArguments.tolower().Contains("-delete"))) {
        

        function Delete-Show-Error {
            $path_exists = Test-Path $args[0]
            if($path_exists) {
                Remove-Item -Recurse -Force -Path $args[0]
            } else {
                Write-Host "    [i] $($args[0]) already deleted"
            }
        }

        Write-Host ""
        Write-Host "[+] Delete Windows Defender (files, services, drivers)"

        Delete-Show-Error "C:\ProgramData\Windows\Windows Defender\"
        Delete-Show-Error "C:\ProgramData\Windows\Windows Defender Advanced Threat Protection\"

        Delete-Show-Error "C:\Windows\System32\drivers\wd\"

        foreach($svc in $svc_list) {
            Delete-Show-Error "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        }

        foreach($drv in $drv_list) {
            Delete-Show-Error "HKLM:\SYSTEM\CurrentControlSet\Services\$drv"
        }
    }
}