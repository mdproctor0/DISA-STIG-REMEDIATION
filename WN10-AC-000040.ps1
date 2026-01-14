 <#
.SYNOPSIS
    This PowerShell script enables password complexity requirements
    to ensure strong password creation.

.NOTES
    Author          : Marquell Proctor
    LinkedIn        : https://www.linkedin.com/in/marquell-proctor-cyber/
    GitHub          : https://github.com/mdproctor0
    Date Created    : 2026-01-14
    Last Modified   : 2026-01-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000040

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. : Windows PowerShell 5.1 (Native Windows 10)

.USAGE
    Example syntax:
    PS C:\> .\WN10-AC-000040.ps1
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
# 1 = Enabled
# 0 = Disabled
# We want this ENABLED.

$RequiredValue = 1

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
    # STEP 4: Update PasswordComplexity value
    # --------------------------------------------------------
    # The line we are looking for looks like:
    # PasswordComplexity = 1

    $Found = $false
    $UpdatedLines = foreach ($line in $CfgLines) {
        if ($line -match '^\s*PasswordComplexity\s*=') {
            $Found = $true
            "PasswordComplexity = $RequiredValue"
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
                $UpdatedLines += "PasswordComplexity = $RequiredValue"
                $Inserted = $true
            }
        }

        if (-not $Inserted) {
            $UpdatedLines += ""
            $UpdatedLines += "[System Access]"
            $UpdatedLines += "PasswordComplexity = $RequiredValue"
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
    $CurrentLine = $VerifyLines | Where-Object { $_ -match '^\s*PasswordComplexity\s*=' } | Select-Object -First 1

    if (-not $CurrentLine) {
        Write-Output "FAIL: Could not find PasswordComplexity in policy."
        exit 2
    }

    $CurrentValue = [int]($CurrentLine -split '=')[1].Trim()

    if ($CurrentValue -eq $RequiredValue) {
        Write-Output "PASS: Password complexity requirements are enabled."
        exit 0
    }
    else {
        Write-Output "FAIL: Password complexity requirements are NOT enabled."
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
 
