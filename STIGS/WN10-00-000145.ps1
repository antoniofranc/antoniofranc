<#
.SYNOPSIS
    Verifies and configures Data Execution Prevention (DEP) to at least OptOut as per STIG WN10-00-000145.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-07
    Last Modified   : 2025-10-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000145
    Rule Title      : Data Execution Prevention (DEP) must be configured to at least OptOut.
    STIG Reference  : https://stigviewer.com/stig/microsoft_windows_10/2023-03-15/

.TESTED ON
    Date(s) Tested  : 2025-10-07
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

    .USAGE
    Run this script as Administrator for proper functionality.
    
    Example syntax:
    PS C:\> .\WN10-00-000145.ps1
    
    Requirements:
    - Administrator privileges
    - PowerShell execution policy allowing script execution
    - Suspend BitLocker before running (if BitLocker is enabled)
    
    #>

# STIG: WN10-00-000145
# Fix: Ensure DEP (Data Execution Prevention) is set to at least "OptOut" or "AlwaysOn"

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run this PowerShell script as Administrator."
    exit
}

Write-Host "Checking DEP configuration..." -ForegroundColor Cyan

# Get current DEP (nx) setting
$depValue = (bcdedit /enum "{current}" | Select-String "nx").ToString().Split()[-1]

if ($depValue -eq "OptOut" -or $depValue -eq "AlwaysOn") {
    Write-Host "✅ DEP is already configured as '$depValue' — compliant (STIG WN10-00-000145)." -ForegroundColor Green
}
else {
    Write-Host "⚠️ DEP is set to '$depValue' — not compliant. Fixing..." -ForegroundColor Yellow
    Write-Host "Suspending BitLocker before making the change is recommended." -ForegroundColor Yellow

    # Configure DEP to OptOut (compliant setting)
    bcdedit /set "{current}" nx OptOut | Out-Null

    # Verify
    $newDepValue = (bcdedit /enum "{current}" | Select-String "nx").ToString().Split()[-1]
    if ($newDepValue -eq "OptOut" -or $newDepValue -eq "AlwaysOn") {
        Write-Host "✅ DEP successfully set to '$newDepValue' (STIG WN10-00-000145)." -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to change DEP setting. Please rerun as Administrator or check BitLocker status." -ForegroundColor Red
    }
}

    
    
