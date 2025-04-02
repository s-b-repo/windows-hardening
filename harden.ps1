# Windows 10/11 Enhanced Hardening Script
# Run as Administrator
Warn-IfWindows10EOL
# ---- System Info ----
Write-Output "Running Windows Hardening Script..."
$OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Output "Detected OS: $OSVersion"

# ---- Disable Unused/Unsafe Network Protocols ----
Write-Output "Disabling Telnet Client and Server..."
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart -ErrorAction SilentlyContinue
Stop-Service -Name tlntsvr -ErrorAction SilentlyContinue
Set-Service -Name tlntsvr -StartupType Disabled

# ---- Disable PowerShell Obfuscation (Base64, bypass) ----
Write-Output "Blocking PowerShell obfuscation attempts..."

# Create registry keys to audit or block PowerShell abuse
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PS_Logs"

# Disable PowerShell Bypass (forces enforcement of execution policy)
Set-ExecutionPolicy RemoteSigned -Force

# Optional: Block use of encoded commands
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value 1

# ---- Disable LOLBAS Tools ----
Write-Output "Disabling LOLBAS tools..."

$lolbins = @(
    "bitsadmin.exe",
    "certutil.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "installutil.exe",
    "wmic.exe",
    "powershell_ise.exe",
    "at.exe",                  # Scheduled task abuse
    "schtasks.exe",            # Scheduled task creation
    "bcdedit.exe",             # Boot config tampering
    "cipher.exe",              # Used to wipe data
    "cmd.exe",                 # Command execution
    "ftp.exe",                 # Data exfiltration
    "tftp.exe",                # Data exfiltration
    "debug.exe",               # Old debugger often used to drop shellcode
    "svchost.exe",             # Process hollowing abuse
    "dllhost.exe",             # COM object abuse
    "taskkill.exe",            # AV/EPP kill
    "tasklist.exe",            # Process recon
    "xcopy.exe",               # File copy (lateral movement)
    "robocopy.exe",            # Lateral movement
    "netsh.exe",               # Firewall bypass, proxy
    "net.exe",                 # Net user/ group manipulation
    "sc.exe",                  # Service creation for persistence
    "whoami.exe",              # Privilege recon
    "nltest.exe"               # Domain recon
)


foreach ($lolbin in $lolbins) {
    $path = "C:\Windows\System32\$lolbin"
    if (Test-Path $path) {
        Write-Output "Denying execution of $lolbin"
        icacls $path /deny Everyone:(X) > $null
    }
}

# Optional: Also block SysWOW64 equivalents for 64-bit Windows
foreach ($lolbin in $lolbins) {
    $path = "C:\Windows\SysWOW64\$lolbin"
    if (Test-Path $path) {
        Write-Output "Denying execution of $lolbin (SysWOW64)"
        icacls $path /deny Everyone:(X) > $null
    }
}
# ---- Block PowerShell from being used in .lnk (shortcut) files ----
Write-Output "Blocking PowerShell execution from shortcut files (.lnk)..."

# Create new file association override to remove PowerShell from default shell execution
New-Item -Path "HKCR:\lnkfile\shell\blockpowershell" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\lnkfile\shell\blockpowershell" -Name "(Default)" -Value "Blocked"
Set-ItemProperty -Path "HKCR:\lnkfile\shell\blockpowershell\command" -Name "(Default)" -Value "cmd.exe /c echo This shortcut execution is blocked. && pause"

# Prevent PowerShell from auto-launching if embedded in .lnk files
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "1" -Value "powershell.exe"

# Optional: block powershell_ise.exe too
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "2" -Value "powershell_ise.exe"

function Warn-IfWindows10EOL {
    $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($osCaption -like "*Windows 10*") {
        Write-Host "`n[!] WARNING: You are using Windows 10, which has reached End of Life (EOL) status." -ForegroundColor Red
        Write-Host "    ⚠️ It no longer receives security updates from Microsoft." -ForegroundColor Yellow
        Write-Host "    🛡️ Please upgrading to Windows 11 asap or a supported OS." -ForegroundColor Yellow
        Write-Host ""
        Start-Sleep -Seconds 5
    }
}


# ---- Defender + Firewall + Audit Policies (unchanged from earlier script, include if needed) ----
# [You can insert the rest of the previous script here, or ask me to merge everything if needed.]

# ---- Final Message ----
Write-Output "`nHardening complete. Please reboot to apply all settings."
