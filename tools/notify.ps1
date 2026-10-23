# Windows toast/dialog for auto-login failures. Used by intercept_addon via
# runpy so a background-thread failure reaches the user's screen instead of
# dying in mitm-out.log.
#
#   powershell -ExecutionPolicy Bypass -File tools\notify.ps1 -Title "..." -Message "..."
#
# Uses msg.exe (built into Windows) rather than a GUI framework: zero deps,
# works from a hidden process, no focus stealing.

param(
    [Parameter(Mandatory = $true)][string]$Title,
    [Parameter(Mandatory = $true)][string]$Message
)

# msg.exe shows the session's own desktop; cap length for readability.
$body = if ($Message.Length -gt 220) { $Message.Substring(0, 220) + "..." } else { $Message }
& msg.exe "$env:USERNAME" "/TIME:60" "$Title`n`n$body"
