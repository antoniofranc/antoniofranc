<#
.SYNOPSIS
    Ensures that FIPS-compliant algorithms are enforced by enabling the "Enabled" value under FIPSAlgorithmPolicy.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-09
    Last Modified   : 2025-10-09
    Version         : 1.0
    STIG-ID         : WN10-SO-000230

.TESTED ON
    Date(s) Tested  : 2025-10-09
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script verifies and enforces the STIG requirement:
        HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled

        - Ensures the registry value "Enabled" is set to 1.
        - Creates or corrects the key if it is missing or misconfigured.

    Example Syntax:
        PS C:\> .\Remediate_WN10-SO-000230.ps1

.WARNING
    Enabling this setting enforces FIPS-compliant algorithms.
    Systems or applications not supporting FIPS algorithms may experience compatibility issues.
#>

# Define registry parameters
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
$ValueName = "Enabled"
$ExpectedValue = 1

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Get current value
$CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

# Check compliance and remediate
if ($CurrentValue -ne $ExpectedValue) {
    if ($null -eq $CurrentValue) {
        Write-Host "❌ Finding: '$ValueName' not found."
    } else {
        Write-Host "❌ Finding: '$ValueName' misconfigured (Current: $CurrentValue)"
    }

    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
    Write-Host "✅ Remediated successfully — '$ValueName' set to 1 (FIPS mode enabled)"
} else {
    Write-Host "✅ Compliant — '$ValueName' is correctly set to 1 (FIPS mode enabled)"
}


