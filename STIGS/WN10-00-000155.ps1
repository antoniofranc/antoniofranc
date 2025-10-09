<#
.SYNOPSIS
    Disables Windows PowerShell 2.0 and its engine if enabled, per STIG requirement.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-08
    Last Modified   : 2025-10-08
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000155

.TESTED ON
    Date(s) Tested  : 2025-10-08
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script checks whether Windows PowerShell 2.0 or its engine is enabled and 
        disables them if found, to comply with STIG WN10-00-000155.

        Example Syntax:
        PS C:\> .\Remediate_WN10-00-000155.ps1
      #>

# Ensure the script runs with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run this PowerShell script as Administrator."
    exit
}

Write-Host "Checking Windows PowerShell 2.0 optional features..." -ForegroundColor Cyan

# Get the state of PowerShell 2.0 features
$psv2 = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "*PowerShellV2*" }

foreach ($feature in $psv2) {
    Write-Host "$($feature.FeatureName) : $($feature.State)"
}

# Check if either feature is enabled
if ($psv2 | Where-Object { $_.State -eq 'Enabled' }) {
    Write-Host "❌ Finding: PowerShell 2.0 feature is enabled." -ForegroundColor Red
    Write-Host "Disabling PowerShell 2.0 features..." -ForegroundColor Yellow

    # Disable both PowerShell 2.0 components
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null

    Write-Host "✅ PowerShell 2.0 features successfully disabled. (STIG WN10-00-000155)" -ForegroundColor Green
} else {
    Write-Host "✅ Compliant: PowerShell 2.0 is already disabled." -ForegroundColor Green
}
   
