 <#
.SYNOPSIS
    This PowerShell script disables the Windows PowerShell 2.0 feature to prevent downgrade attacks
    and ensure modern security logging is enforced.

.NOTES
    Author          : Marquell Proctor
    LinkedIn        : https://www.linkedin.com/in/marquell-proctor-cyber/
    GitHub          : https://github.com/mdproctor0
    Date Created    : 2026-01-14
    Last Modified   : 2026-01-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000155

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. : Windows PowerShell 5.1 (Native Windows 10)

.USAGE
    Example syntax:
    PS C:\> .\WN10-00-000155.ps1
#>

# ------------------------------------------------------------
# STEP 1: Make sure the script is being run as Administrator
# ------------------------------------------------------------
# Some Windows settings are protected.
# If we are not an administrator, Windows will block the change.

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal   = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
$IsAdmin     = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}
# ------------------------------------------------------------
# STEP 2: Define the PowerShell 2.0 feature names
# ------------------------------------------------------------
# Windows treats PowerShell 2.0 as optional features.
# We store their names in variables so we don’t have to retype them.

$FeatureRoot   = "MicrosoftWindowsPowerShellV2Root"
$FeatureEngine = "MicrosoftWindowsPowerShellV2"

try {
    # --------------------------------------------------------
    # STEP 3: Disable PowerShell 2.0
    # --------------------------------------------------------
    # These commands turn OFF PowerShell 2.0.
    # -Online means we are changing the currently running system.
    # -NoRestart means the computer will not reboot automatically.

    Disable-WindowsOptionalFeature -Online -FeatureName $FeatureRoot   -NoRestart -ErrorAction Stop | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName $FeatureEngine -NoRestart -ErrorAction Stop | Out-Null

    # --------------------------------------------------------
    # STEP 4: Verify the setting
    # --------------------------------------------------------
    # Now we check Windows to make sure PowerShell 2.0 is really disabled.

    $RootState   = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureRoot).State
    $EngineState = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureEngine).State

    # --------------------------------------------------------
    # STEP 5: Print PASS or FAIL
    # --------------------------------------------------------
    # If BOTH features are disabled, the STIG requirement is met.

    if ($RootState -eq "Disabled" -and $EngineState -eq "Disabled") {
        Write-Output "PASS: PowerShell 2.0 is disabled."
        Write-Output "INFO: $FeatureRoot State   = $RootState"
        Write-Output "INFO: $FeatureEngine State = $EngineState"
        exit 0
    }
    else {
        Write-Output "FAIL: PowerShell 2.0 is NOT fully disabled."
        Write-Output "INFO: $FeatureRoot State   = $RootState"
        Write-Output "INFO: $FeatureEngine State = $EngineState"
        exit 2
    }
}
catch {
    # --------------------------------------------------------
    # STEP 6: Error handling
    # --------------------------------------------------------
    # If something goes wrong, show the error message clearly.

    Write-Error "Error applying or verifying the STIG: $($_.Exception.Message)"
    exit 3
}
 
