<#
.SYNOPSIS
    This PowerShell script disables the Secondary Logon service (seclogon) to reduce the risk of running programs under alternate user accounts.

.NOTES
    Author          : Marquell Proctor
    LinkedIn        : https://www.linkedin.com/in/marquell-proctor-cyber/
    GitHub          : https://github.com/mdproctor0
    Date Created    : 2026-01-14
    Last Modified   : 2026-01-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000175

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. : Windows PowerShell 5.1 (Native Windows 10)

.USAGE
    Example syntax:
    PS C:\> .\WN10-00-000175.ps1
#>

# ------------------------------------------------------------
# STEP 1: Make sure the script is being run as Administrator
# ------------------------------------------------------------
# We need admin rights to change Windows services.

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal   = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
$IsAdmin     = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# ------------------------------------------------------------
# STEP 2: Define the service name
# ------------------------------------------------------------
# The display name is "Secondary Logon"
# The real service name Windows uses is usually "seclogon"

$ServiceName = "seclogon"

try {
    # --------------------------------------------------------
    # STEP 3: Confirm the service exists
    # --------------------------------------------------------
    $Svc = Get-Service -Name $ServiceName -ErrorAction Stop

    # --------------------------------------------------------
    # STEP 4: Stop the service (if it is running)
    # --------------------------------------------------------
    # If it's running, we stop it so it isn't active anymore.
    if ($Svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    }

    # --------------------------------------------------------
    # STEP 5: Disable the service so it won't start again
    # --------------------------------------------------------
    Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop

    # --------------------------------------------------------
    # STEP 6: Verify the service is disabled and stopped
    # --------------------------------------------------------
    $SvcAfter = Get-Service -Name $ServiceName -ErrorAction Stop
    $StartMode = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop).StartMode

    $IsStopped  = ($SvcAfter.Status -ne "Running")
    $IsDisabled = ($StartMode -eq "Disabled")

    if ($IsStopped -and $IsDisabled) {
        Write-Output "PASS: Secondary Logon service is disabled and not running."
        Write-Output "INFO: Service Name  = $ServiceName"
        Write-Output "INFO: Status        = $($SvcAfter.Status)"
        Write-Output "INFO: StartMode     = $StartMode"
        exit 0
    }
    else {
        Write-Output "FAIL: Secondary Logon service is NOT in the required state."
        Write-Output "INFO: Service Name  = $ServiceName"
        Write-Output "INFO: Status        = $($SvcAfter.Status)"
        Write-Output "INFO: StartMode     = $StartMode"
        exit 2
    }
}
catch {
    Write-Error "Error applying or verifying the STIG: $($_.Exception.Message)"
    exit 3
}
