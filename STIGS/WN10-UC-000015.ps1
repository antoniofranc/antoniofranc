<#
.SYNOPSIS
    This PowerShell script ensures that toast notifications on the lock screen are turned off.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-09
    Last Modified   : 2025-10-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-UC-000015

.TESTED ON
    Date(s) Tested  : 2025-10-09
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script ensures toast notifications are disabled on the lock screen
        in compliance with STIG ID WN10-UC-000015 by setting the registry value
        NoToastApplicationNotificationOnLockScreen to 1.

    Example Syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-UC-000015).ps1
  #>

  # Quick check - returns $true if compliant
(Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -ErrorAction SilentlyContinue).NoToastApplicationNotificationOnLockScreen -eq 1

# Quick enable - sets the policy to Enabled
if (-not (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) { New-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force }; Set-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWORD -Force; Write-Host "Policy 'Turn off toast notifications on lock screen' has been Enabled" -ForegroundColor Green




    
