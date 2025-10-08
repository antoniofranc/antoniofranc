<#
.SYNOPSIS
    Verifies the "Reset account lockout counter after" setting is configured to 15 minutes or greater.

.NOTES
    Author          : Antonio Francisco
    LinkedIn        : linkedin.com/in/antoniofrancisco-085948210
    GitHub          : github.com/antoniofranc
    Date Created    : 2025-10-07
    Last Modified   : 2025-10-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000015
    
.TESTED ON
    Date(s) Tested  : 2025-10-07
    Tested By       : Antonio Francisco
    Systems Tested  : Windows 10 22H2
    PowerShell Ver. : 5.1

.USAGE
    Run this script as Administrator for accurate results.
    
    Example syntax:
    PS C:\> .\WN10-AC-000015.ps1
#>

Write-Host "Setting Reset Account Lockout Counter to 15 minutes..." -ForegroundColor Yellow

$temp = "$env:TEMP\secpol.cfg"

# Export current policy
secedit /export /cfg $temp | Out-Null

# Check current value
$currentValue = [int]((Select-String "ResetLockoutCount" $temp).Line.Split('=')[1].Trim())
Write-Host "Current value: $currentValue minutes" -ForegroundColor White

if ($currentValue -lt 15) {
    # Update the policy file
    $content = Get-Content $temp
    $content = $content -replace 'ResetLockoutCount\s*=\s*\d+', 'ResetLockoutCount = 15'
    $content | Set-Content $temp
    
    # Apply the new policy
    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $temp /areas SECURITYPOLICY | Out-Null
    
    # Force group policy update
    gpupdate /force | Out-Null
    
    # Verify the change
    secedit /export /cfg $temp | Out-Null
    $newValue = [int]((Select-String "ResetLockoutCount" $temp).Line.Split('=')[1].Trim())
    
    if ($newValue -eq 15) {
        Write-Host " SUCCESS: Reset account lockout counter set to 15 minutes" -ForegroundColor Green
    } else {
        Write-Host " FAILED: Could not verify the change" -ForegroundColor Red
    }
} else {
    Write-Host " Already compliant: $currentValue minutes" -ForegroundColor Green
}

# Cleanup
Remove-Item $temp -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secedit.sdb" -ErrorAction SilentlyContinue



