<#
.SYNOPSIS
    Verifies and configures the minimum BitLocker PIN length to 6 characters or greater as per STIG WN10-00-000032.

    .DESCRIPTION
    This PowerShell script checks and configures the minimum PIN length for BitLocker startup authentication
    to ensure it is set to at least 6 characters to comply with STIG security requirements.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-07
    Last Modified   : 2025-10-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000032

.TESTED ON
    Date(s) Tested  : 2025-10-07
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

 .USAGE
    Run this script as Administrator for proper functionality.
    
    Example syntax:
    PS C:\> .\WN10-00-000032.ps1
    
    Requirements:
    - Administrator privileges
  #>

  
# STIG: WN10-00-000032
# Fix: Configure minimum BitLocker startup PIN length (6 or greater)

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "Run this PowerShell script as Administrator."
    exit
}

# Registry path for BitLocker policy
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Create path if missing
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Set minimum PIN length to 6
Set-ItemProperty -Path $regPath -Name "MinimumPIN" -Value 6 -Type DWord

Write-Host "BitLocker minimum startup PIN length configured to 6 (STIG WN10-00-000032)."
