<#
.SYNOPSIS
    Verifies and configures the Secondary Logon service to be disabled as per STIG WN10-00-000175.

.DESCRIPTION
    This PowerShell script checks and configures the Secondary Logon service (seclogon) 
    to ensure it is disabled and not running to comply with STIG security requirements.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-07
    Last Modified   : 2025-10-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000175

.TESTED ON
    Date(s) Tested  : 2025-10-07
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Run this script as Administrator for proper functionality.
    
    Example syntax:
    PS C:\> .\WN10-00-000175.ps1

 Requirements:
    - Administrator privileges
    - PowerShell execution policy allowing script execution
  #>


# STIG: WN10-00-000175
# Fix: Disable and stop the "Secondary Logon" service

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run this PowerShell script as Administrator."
    exit
}

$serviceName = "seclogon"

# Stop the service if it's running
if ((Get-Service -Name $serviceName).Status -eq 'Running') {
    Stop-Service -Name $serviceName -Force
    Write-Host "Stopped the 'Secondary Logon' service."
}

# Disable the service
Set-Service -Name $serviceName -StartupType Disabled
Write-Host "'Secondary Logon' service startup type set to Disabled (STIG WN10-00-000175)."


    

    


    
