<#
.SYNOPSIS
    Configures BitLocker to require additional authentication at startup as per STIG WN10-00-000031.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-07
    Last Modified   : 2025-10-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000031

.TESTED ON
    Date(s) Tested  : 2025-10-07
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Run this script as Administrator for proper functionality.
    
    Example syntax:
    PS C:\> .\WN10-00-000031.ps1
  #>

  # STIG: WN10-00-000031
# Fix: Require additional authentication at startup (TPM + PIN)

# Ensure running as Administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "Run this PowerShell script as Administrator."
    Exit
}

# Create or edit the Local Group Policy for BitLocker OS drives
$gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Enable "Require additional authentication at startup"
Set-ItemProperty -Path $gpoPath -Name "UseAdvancedStartup" -Value 1 -Type DWord

# Configure TPM startup PIN requirement (Require startup PIN with TPM)
Set-ItemProperty -Path $gpoPath -Name "UseTPM" -Value 2 -Type DWord
Set-ItemProperty -Path $gpoPath -Name "UseTPMKeyPIN" -Value 2 -Type DWord

Write-Host "BitLocker policy configured: Require TPM + PIN at startup (STIG WN10-00-000031)."



    
