param(
    [Parameter(Mandatory = $true)][string]$OutPath,
    [int]$SinceHours = 24
)

$processes = Get-CimInstance Win32_Process | ForEach-Object {
    $owner = $null
    try {
        $ownerObj = $_ | Invoke-CimMethod -MethodName GetOwner
        if ($ownerObj.ReturnValue -eq 0) {
            $owner = "$($ownerObj.Domain)\$($ownerObj.User)"
        }
    } catch {
        $owner = $null
    }

    $sigStatus = $null
    if ($_.ExecutablePath) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $_.ExecutablePath
            $sigStatus = $sig.Status.ToString()
        } catch {
            $sigStatus = "Unknown"
        }
    }

    [PSCustomObject]@{
        name = $_.Name
        pid = $_.ProcessId
        path = $_.ExecutablePath
        command_line = $_.CommandLine
        owner = $owner
        signature_status = $sigStatus
    }
}

$startupItems = Get-CimInstance Win32_StartupCommand | ForEach-Object {
    $sigStatus = $null
    if ($_.Command) {
        $exePath = $_.Command.Split(" ")[0].Trim('"')
        if (Test-Path $exePath) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $exePath
                $sigStatus = $sig.Status.ToString()
            } catch {
                $sigStatus = "Unknown"
            }
        }
    }
    [PSCustomObject]@{
        name = $_.Name
        command = $_.Command
        location = $_.Location
        user = $_.User
        signature_status = $sigStatus
    }
}

$scheduledTasks = Get-ScheduledTask | ForEach-Object {
    $action = $null
    if ($_.Actions -and $_.Actions.Count -gt 0) {
        $action = $_.Actions[0].Execute
    }
    [PSCustomObject]@{
        name = $_.TaskName
        path = $_.TaskPath
        state = $_.State.ToString()
        action = $action
    }
}

$services = Get-Service | ForEach-Object {
    [PSCustomObject]@{
        name = $_.Name
        display_name = $_.DisplayName
        status = $_.Status.ToString()
        start_type = $_.StartType.ToString()
    }
}

$tcpConnections = Get-NetTCPConnection | ForEach-Object {
    $procName = $null
    $sigStatus = $null
    try {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction Stop
        $procName = $proc.Name
        if ($proc.Path) {
            $sig = Get-AuthenticodeSignature -FilePath $proc.Path
            $sigStatus = $sig.Status.ToString()
        }
    } catch {
        $procName = $null
        $sigStatus = "Unknown"
    }
    [PSCustomObject]@{
        local_address = $_.LocalAddress
        local_port = $_.LocalPort
        remote_address = $_.RemoteAddress
        remote_port = $_.RemotePort
        state = $_.State.ToString()
        process_name = $procName
        signature_status = $sigStatus
    }
}

$eventLogs = @()
try {
    $since = (Get-Date).AddHours(-$SinceHours)
    $filters = @(
        @{LogName = "System"; StartTime = $since; Id = 7045},
        @{LogName = "Security"; StartTime = $since; Id = 4698},
        @{LogName = "Security"; StartTime = $since; Id = 4720},
        @{LogName = "Security"; StartTime = $since; Id = 4625},
        @{LogName = "Security"; StartTime = $since; Id = 1102},
        @{LogName = "Microsoft-Windows-PowerShell/Operational"; StartTime = $since; Id = 4104}
    )
    foreach ($filter in $filters) {
        try {
            $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
            foreach ($event in $events) {
                $eventLogs += [PSCustomObject]@{
                    log = $filter.LogName
                    id = $event.Id
                    level = $event.LevelDisplayName
                    time = $event.TimeCreated.ToString("o")
                    provider = $event.ProviderName
                    message = $event.Message
                }
            }
        } catch {
        }
    }
} catch {
}

$payload = [PSCustomObject]@{
    generated_at = (Get-Date).ToString("o")
    hostname = $env:COMPUTERNAME
    processes = $processes
    startup_items = $startupItems
    scheduled_tasks = $scheduledTasks
    services = $services
    tcp_connections = $tcpConnections
    event_logs = $eventLogs
}

$payload | ConvertTo-Json -Depth 5 | Set-Content -Path $OutPath -Encoding UTF8
