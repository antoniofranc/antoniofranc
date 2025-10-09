<#
.SYNOPSIS
    This PowerShell script ensures that User Account Control (UAC) behavior for standard users is set to automatically deny elevation requests.
    
.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-09
    Last Modified   : 2025-10-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000255

.TESTED ON
    Date(s) Tested  : 2025-10-09
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Description:
        This script ensures that UAC is configured to automatically deny elevation
        requests for standard users in compliance with STIG ID WN10-SO-000255 by
        setting the registry value ConsentPromptBehaviorUser to 0.
        
Example Syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-SO-000255).ps1
#>

# Quick WN10-SO-000255 Check
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "ConsentPromptBehaviorUser"

try {
    $value = Get-ItemPropertyValue -Path $path -Name $valueName -ErrorAction Stop
    if ($value -eq 0) {
        Write-Host "COMPLIANT: ConsentPromptBehaviorUser is set to 0" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "NON-COMPLIANT: ConsentPromptBehaviorUser is set to $value (should be 0)" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "NON-COMPLIANT: ConsentPromptBehaviorUser does not exist or cannot be read" -ForegroundColor Red
    exit 1
}


    
        
