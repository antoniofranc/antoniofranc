<#
.SYNOPSIS
    Checks and enforces that "Enforce password history" is set to at least 24 passwords remembered.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-08
    Last Modified   : 2025-10-08
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000020

.TESTED ON
    Date(s) Tested  : 2025-10-08
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

    .USAGE
    Description:
        This script verifies that the "Enforce password history" policy remembers at least
        24 previous passwords. If the setting is lower, it automatically updates it to 24.

    Example Syntax:
        PS C:\> .\Remediate_WN10-AC-000020.ps1

 
#>

# Enforce password history policy to 24 passwords remembered
$domainPolicy = secedit /export /cfg "$env:TEMP\secpol.cfg"
(Get-Content "$env:TEMP\secpol.cfg") `
    -replace 'PasswordHistorySize = \d+', 'PasswordHistorySize = 24' |
    Set-Content "$env:TEMP\secpol.cfg"

secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY
Remove-Item "$env:TEMP\secpol.cfg" -Force
Write-Host "Password history policy set to 24 passwords remembered."

