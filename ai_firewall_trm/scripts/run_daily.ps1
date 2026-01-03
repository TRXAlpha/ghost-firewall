param(
    [Parameter(Mandatory = $true)][string]$LogPath,
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [Parameter(Mandatory = $true)][string]$OutJson,
    [string]$OutText
)

python "$PSScriptRoot\..\src\ai_firewall\cli.py" --log $LogPath --config $ConfigPath --out $OutJson --text $OutText
