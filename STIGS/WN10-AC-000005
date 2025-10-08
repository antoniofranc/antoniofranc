<#
.SYNOPSIS
    Configures the account lockout duration to 15 minutes or greater for Windows 10 systems.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-07
    Last Modified   : 2025-10-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 2025-10-07
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Run this script as Administrator for proper functionality.
    Example syntax:
    PS C:\> .\WN10-AC-000005.ps1
#>

# Check and fix Account Lockout Duration
$temp = "$env:TEMP\secpol.cfg"
secedit /export /cfg $temp | Out-Null
$duration = [int]((Select-String "LockoutDuration" $temp).ToString().Split('=')[1].Trim())

if ($duration -eq 0) {
    Write-Host "✅ Compliant: 0 (admin unlock required)."
} elseif ($duration -lt 15) {
    Write-Host "❌ Finding: Duration is $duration. Setting to 15..."
    (Get-Content $temp) -replace 'LockoutDuration\s*=\s*\d+', 'LockoutDuration = 15' | Set-Content $temp
    secedit /configure /db secedit.sdb /cfg $temp /areas SECURITYPOLICY | Out-Null
    gpupdate /force | Out-Null
    Write-Host "✅ Updated to 15 minutes."
} else {
    Write-Host "✅ Compliant: $duration minutes."
}

Remove-Item $temp -ErrorAction SilentlyContinue
