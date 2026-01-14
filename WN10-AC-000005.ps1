<#
.SYNOPSIS
    This PowerShell script configures the Account Lockout Duration to 15 minutes to reduce the risk of brute-force password attempts.

.NOTES
    Author          : Marquell Proctor
    LinkedIn        : https://www.linkedin.com/in/marquell-proctor-cyber/
    GitHub          : https://github.com/mdproctor0
    Date Created    : 2026-01-14
    Last Modified   : 2026-01-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. : Windows PowerShell 5.1 (Native Windows 10)

.USAGE
    Example syntax:
    PS C:\> .\WN10-AC-000005.ps1
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
# STEP 2: Define what we want (15 minutes)
# ------------------------------------------------------------
# Think of this like a rule:
# "If someone gets locked out, they stay locked out for 15 minutes."

$RequiredMinutes = 15

# Temporary files we will create and then delete
$TempCfg = Join-Path $env:TEMP "secpol_export.cfg"
$DbFile  = Join-Path $env:TEMP "secpol.sdb"

try {
    # --------------------------------------------------------
    # STEP 3: Export current security policy to a text file
    # --------------------------------------------------------
    # This creates a readable file we can edit safely.
    secedit /export /cfg $TempCfg /areas SECURITYPOLICY | Out-Null

    if (-not (Test-Path $TempCfg)) {
        throw "Failed to export security policy."
    }

    $CfgLines = Get-Content -Path $TempCfg -ErrorAction Stop

    # --------------------------------------------------------
    # STEP 4: Update the LockoutDuration value in the file
    # --------------------------------------------------------
    # The line we want looks like:
    # LockoutDuration = 15

    $Found = $false
    $UpdatedLines = foreach ($line in $CfgLines) {
        if ($line -match '^\s*LockoutDuration\s*=') {
            $Found = $true
            "LockoutDuration = $RequiredMinutes"
        }
        else {
            $line
        }
    }

    # If the line didn't exist (rare), add it under [System Access]
    if (-not $Found) {
        $UpdatedLines = @()
        $Inserted = $false

        foreach ($line in $CfgLines) {
            $UpdatedLines += $line

            if ($line -match '^\[System Access\]\s*$' -and -not $Inserted) {
                $UpdatedLines += "LockoutDuration = $RequiredMinutes"
                $Inserted = $true
            }
        }

        if (-not $Inserted) {
            # If [System Access] section wasn’t found, append it
            $UpdatedLines += ""
            $UpdatedLines += "[System Access]"
            $UpdatedLines += "LockoutDuration = $RequiredMinutes"
        }
    }

    Set-Content -Path $TempCfg -Value $UpdatedLines -ErrorAction Stop

    # --------------------------------------------------------
    # STEP 5: Apply the updated security policy back to Windows
    # --------------------------------------------------------
    secedit /configure /db $DbFile /cfg $TempCfg /areas SECURITYPOLICY /quiet | Out-Null

    # Optional: refresh policy (helps some scanners pick it up faster)
    gpupdate /force | Out-Null

    # --------------------------------------------------------
    # STEP 6: Verify (export again and confirm value)
    # --------------------------------------------------------
    secedit /export /cfg $TempCfg /areas SECURITYPOLICY | Out-Null
    $VerifyLines = Get-Content -Path $TempCfg -ErrorAction Stop
    $CurrentLine = $VerifyLines | Where-Object { $_ -match '^\s*LockoutDuration\s*=' } | Select-Object -First 1

    if (-not $CurrentLine) {
        Write-Output "FAIL: Could not find LockoutDuration in exported policy."
        exit 2
    }

    $CurrentValue = [int]($CurrentLine -split '=')[1].Trim()

    if ($CurrentValue -ge $RequiredMinutes) {
        Write-Output "PASS: Account lockout duration is $CurrentValue minutes (Required: >= $RequiredMinutes)."
        exit 0
    }
    else {
        Write-Output "FAIL: Account lockout duration is $CurrentValue minutes (Required: >= $RequiredMinutes)."
        exit 2
    }
}
catch {
    Write-Error "Error applying or verifying the STIG: $($_.Exception.Message)"
    exit 3
}
finally {
    # Clean up temp file (optional, but keeps things tidy)
    if (Test-Path $TempCfg) { Remove-Item $TempCfg -Force -ErrorAction SilentlyContinue }
}
