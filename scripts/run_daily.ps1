param(
    [Parameter(Mandatory = $true)][string]$LogPath,
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [Parameter(Mandatory = $true)][string]$StateDir,
    [switch]$AutoBlock
)

# Daily run: refresh threat feeds, analyze the log, write report + blocklist
# into $StateDir. Point Pi-hole at $StateDir\blocklist.txt (see README).
$cli = @(
    "$PSScriptRoot\..\src\ai_firewall\cli.py",
    "--log", $LogPath,
    "--config", $ConfigPath,
    "--state-dir", $StateDir,
    "--update-intel"
)
if ($AutoBlock) { $cli += "--auto-block" }
python @cli
exit $LASTEXITCODE
