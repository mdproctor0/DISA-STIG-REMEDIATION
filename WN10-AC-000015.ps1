 <#
.SYNOPSIS
    This PowerShell script configures the reset account lockout counter value to 15 minutes
    to prevent rapid brute-force authentication attempts.

.NOTES
    Author          : Marquell Proctor
    LinkedIn        : https://www.linkedin.com/in/marquell-proctor-cyber/
    GitHub          : https://github.com/mdproctor0
    Date Created    : 2026-01-14
    Last Modified   : 2026-01-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000015

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. : Windows PowerShell 5.1 (Native Windows 10)

.USAGE
    Example syntax:
    PS C:\> .\WN10-AC-000015.ps1
#>

# ------------------------------------------------------------
# STEP 1: Make sure the script is being run as Administrator
# ------------------------------------------------------------
# We need admin rights to change local security policy settings.

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal   = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
$IsAdmin     = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# ------------------------------------------------------------
# STEP 2: Define the required value
# ------------------------------------------------------------
# This means:
# "After an account locks, wait 15 minutes before resetting the counter."

$RequiredMinutes = 15

# Temporary files used to safely update security policy
$TempCfg = Join-Path $env:TEMP "secpol_export.cfg"
$DbFile  = Join-Path $env:TEMP "secpol.sdb"

try {
    # --------------------------------------------------------
    # STEP 3: Export the current local security policy
    # --------------------------------------------------------
    secedit /export /cfg $TempCfg /areas SECURITYPOLICY | Out-Null

    if (-not (Test-Path $TempCfg)) {
        throw "Failed to export security policy."
    }

    $CfgLines = Get-Content -Path $TempCfg -ErrorAction Stop

    # --------------------------------------------------------
    # STEP 4: Update ResetLockoutCount value
    # --------------------------------------------------------
    # The line we are looking for looks like:
    # ResetLockoutCount = 15

    $Found = $false
    $UpdatedLines = foreach ($line in $CfgLines) {
        if ($line -match '^\s*ResetLockoutCount\s*=') {
            $Found = $true
            "ResetLockoutCount = $RequiredMinutes"
        }
        else {
            $line
        }
    }

    # If the value does not exist, add it under [System Access]
    if (-not $Found) {
        $UpdatedLines = @()
        $Inserted = $false

        foreach ($line in $CfgLines) {
            $UpdatedLines += $line

            if ($line -match '^\[System Access\]\s*$' -and -not $Inserted) {
                $UpdatedLines += "ResetLockoutCount = $RequiredMinutes"
                $Inserted = $true
            }
        }

        if (-not $Inserted) {
            $UpdatedLines += ""
            $UpdatedLines += "[System Access]"
            $UpdatedLines += "ResetLockoutCount = $RequiredMinutes"
        }
    }

    Set-Content -Path $TempCfg -Value $UpdatedLines -ErrorAction Stop

    # --------------------------------------------------------
    # STEP 5: Apply the updated policy
    # --------------------------------------------------------
    secedit /configure /db $DbFile /cfg $TempCfg /areas SECURITYPOLICY /quiet | Out-Null
    gpupdate /force | Out-Null

    # --------------------------------------------------------
    # STEP 6: Verify the setting
    # --------------------------------------------------------
    secedit /export /cfg $TempCfg /areas SECURITYPOLICY | Out-Null
    $VerifyLines = Get-Content -Path $TempCfg -ErrorAction Stop
    $CurrentLine = $VerifyLines | Where-Object { $_ -match '^\s*ResetLockoutCount\s*=' } | Select-Object -First 1

    if (-not $CurrentLine) {
        Write-Output "FAIL: Could not find ResetLockoutCount in policy."
        exit 2
    }

    $CurrentValue = [int]($CurrentLine -split '=')[1].Trim()

    if ($CurrentValue -ge $RequiredMinutes) {
        Write-Output "PASS: Reset account lockout counter is $CurrentValue minutes (Required: >= $RequiredMinutes)."
        exit 0
    }
    else {
        Write-Output "FAIL: Reset account lockout counter is $CurrentValue minutes (Required: >= $RequiredMinutes)."
        exit 2
    }
}
catch {
    Write-Error "Error applying or verifying the STIG: $($_.Exception.Message)"
    exit 3
}
finally {
    if (Test-Path $TempCfg) { Remove-Item $TempCfg -Force -ErrorAction SilentlyContinue }
}
 
