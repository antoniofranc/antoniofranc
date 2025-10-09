<#
.SYNOPSIS
    Ensures the 'SupportedEncryptionTypes' registry value is configured per STIG ID WN10-SO-000190.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub           : github.com/antoniofranc
    Date Created    : 2025-10-09
    Last Modified   : 2025-10-09
    Version         : 1.0
    STIG-ID         : WN10-SO-000190

.TESTED ON
    Date(s) Tested  : 2025-10-09
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script verifies and enforces the STIG requirement for:
        HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
        SupportedEncryptionTypes

        - Ensures value is 0x7ffffff8 (2147483640).
        - Creates the registry key if missing.

         Example Syntax:
        PS C:\> .\Remediate_WN10-SO-000190.ps1
#>

# Define STIG parameters
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$valueName = "SupportedEncryptionTypes"
$expectedValue = 2147483640  # 0x7ffffff8

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Host "Creating registry path: $regPath"
    New-Item -Path $regPath -Force | Out-Null
}

# Get current value if it exists
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

# Compare and remediate
if ($currentValue -ne $expectedValue) {
    if ($null -eq $currentValue) {
        Write-Host "❌ Finding: '$valueName' not found."
    } else {
        Write-Host "❌ Finding: '$valueName' misconfigured (Current: $currentValue)"
    }

    # Apply fix
    Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
    Write-Host "✅ Remediated successfully — '$valueName' set to $expectedValue (0x7ffffff8)"
} else {
    Write-Host "✅ Compliant — '$valueName' is correctly set to $expectedValue (0x7ffffff8)"
}

        
