<#
.SYNOPSIS
    Ensures the RestrictRemoteSAM registry value is properly configured per STIG ID WN10-SO-000167.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-09
    Last Modified   : 2025-10-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000167

.TESTED ON
    Date(s) Tested  : 2025-10-09
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script verifies that the registry value RestrictRemoteSAM is correctly configured
        under HKLM:\SYSTEM\CurrentControlSet\Control\Lsa.

        If missing or misconfigured, it sets it to the required STIG-compliant value:
        O:BAG:BAD:(A;;RC;;;BA)

            Example Syntax:
        PS C:\> .\Remediate_WN10-SO-000167.ps1
#>

# Define STIG parameters
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "RestrictRemoteSAM"
$expectedValue = "O:BAG:BAD:(A;;RC;;;BA)"

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Host "Creating registry path: $regPath"
    New-Item -Path $regPath -Force | Out-Null
}

# Get the current value if it exists
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($currentValue -ne $expectedValue) {
    if ($null -eq $currentValue) {
        Write-Host "❌ Finding: RestrictRemoteSAM not found."
    } else {
        Write-Host "❌ Finding: RestrictRemoteSAM misconfigured (Current: $currentValue)"
    }

    # Apply the fix
    Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type String
    Write-Host "✅ Remediated successfully to: $expectedValue"
} else {
    Write-Host "✅ Compliant: RestrictRemoteSAM is correctly set to $expectedValue"
}


        

