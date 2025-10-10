.SYNOPSIS
    Ensures the local Administrator account runs with a filtered token (UAC enabled for the Administrator account).

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-09
    Last Modified   : 2025-10-09
    Version         : 1.0
    STIG-ID         : WN10-SO-000245
    
.TESTED ON
    Date(s) Tested  : 2025-10-09
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script verifies and enforces the STIG requirement for:
        HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\AllowOnlineID

        - If missing or misconfigured, sets the value to 0 (Disabled).
        - Ensures compliance with STIG WN10-SO-000185.

    Example Syntax:
        PS C:\> .\Remediate_WN10-SO-000185.ps1
#>

# Define STIG parameters
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u"
$valueName = "AllowOnlineID"
$expectedValue = 0

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Host "Creating registry path: $regPath"
    New-Item -Path $regPath -Force | Out-Null
}

# Get current value if present
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

# Compare and remediate
if ($currentValue -ne $expectedValue) {
    if ($null -eq $currentValue) {
        Write-Host "❌ Finding: '$valueName' not found."
    } else {
        Write-Host "❌ Finding: '$valueName' misconfigured (Current: $currentValue)"
    }

    # Apply the fix
    Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
    Write-Host "✅ Remediated successfully to value: $expectedValue"
} else {
    Write-Host "✅ Compliant: '$valueName' is correctly set to $expectedValue"
}
