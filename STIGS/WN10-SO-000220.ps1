<#
.SYNOPSIS
    Ensures the 'NTLMMinServerSec' registry value is configured to 0x20080000 (537395200), per STIG ID WN10-SO-000220.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-09
    Last Modified   : 2025-10-09
    Version         : 1.0
    STIG-ID         : WN10-SO-000220

.TESTED ON
    Date(s) Tested  : 2025-10-09
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script verifies and enforces the STIG requirement for:
        HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
        NTLMMinServerSec

        - Ensures the value is 0x20080000 (537395200).
        - Creates or corrects the registry value if missing or incorrect.

         Example Syntax:
        PS C:\> .\Remediate_WN10-SO-000220.ps1
  #>

  # Define registry parameters
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$ValueName = "NTLMMinServerSec"
$ExpectedValue = 0x20080000  # 537395200

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    Write-Host "Creating registry path: $RegPath"
    New-Item -Path $RegPath -Force | Out-Null
}

# Get current registry value
$CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

# Check compliance and remediate
if ($CurrentValue -ne $ExpectedValue) {
    if ($null -eq $CurrentValue) {
        Write-Host "❌ Finding: '$ValueName' not found."
    } else {
        Write-Host "❌ Finding: '$ValueName' misconfigured (Current: $CurrentValue)"
    }

    # Apply fix
    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
    Write-Host "✅ Remediated successfully — '$ValueName' set to 0x20080000 (537395200)"
} else {
    Write-Host "✅ Compliant — '$ValueName' is correctly set to 0x20080000 (537395200)"
}

  
