# Read-only sampler: attach to an already running process. Never starts/stops apps.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateRange(1,2147483647)][int]$ProcessId,
    [Parameter(Mandatory=$true)][ValidateSet('AITaskManager','Argus')][string]$Label,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$Revision,
    [Parameter(Mandatory=$true)][string]$Scenario,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateRange(10,10000)][int]$Samples = 120,
    [ValidateRange(100,60000)][int]$IntervalMs = 1000
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This benchmark requires Windows.' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new output directory; previous evidence is never overwritten.' }
$initial = Get-Process -Id $ProcessId -ErrorAction Stop
$started = $initial.StartTime.ToUniversalTime()
$exe = $initial.Path
if (-not $exe) { throw 'Executable path is unreadable; cannot pin binary identity.' }
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $ExpectedSha256.ToLowerInvariant()) { throw 'Executable SHA256 does not match the supplied pin.' }
$osInfo = Get-CimInstance Win32_OperatingSystem
$cpuInfo = @(Get-CimInstance Win32_Processor)
$system = Get-CimInstance Win32_ComputerSystem
$logical = [int]$system.NumberOfLogicalProcessors
if ($logical -lt 1) { throw 'Cannot determine logical processor count.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$metadata = [ordered]@{
    schemaVersion = 1; label = $Label; revision = $Revision; scenario = $Scenario
    executable = $exe; sha256 = $hash; fileVersion = $initial.FileVersionInfo.FileVersion
    processId = $ProcessId; processStartUtc = $started.ToString('o')
    measurementStartUtc = [DateTime]::UtcNow.ToString('o'); measurementEndUtc = $null
    osVersion = $osInfo.Version; osBuild = $osInfo.BuildNumber
    cpu = @($cpuInfo | ForEach-Object { $_.Name }); logicalProcessors = $logical
    totalMemoryBytes = [double]$system.TotalPhysicalMemory
    powershellVersion = $PSVersionTable.PSVersion.ToString()
    requestedSamples = $Samples; intervalMs = $IntervalMs; actualSamples = 0
    scope = 'root process only; child processes excluded'
    status = 'RUNNING'; error = $null
}
$metadataPath = Join-Path $OutputDirectory 'metadata.json'
$metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
$rows = New-Object 'System.Collections.Generic.List[object]'
$csv = Join-Path $OutputDirectory 'samples.csv'
$watch = [Diagnostics.Stopwatch]::StartNew()
$lastTime = $watch.Elapsed.TotalSeconds
$lastCpu = $initial.TotalProcessorTime.TotalSeconds
function Percentile([double[]]$Values, [double]$P) {
    $sorted = @($Values | Sort-Object)
    if ($sorted.Count -eq 0) { return $null }
    # Nearest-rank, explicitly shared by median and p95.
    $index = [Math]::Max(0, [int][Math]::Ceiling($P * $sorted.Count) - 1)
    return $sorted[$index]
}
try {
    for ($i = 0; $i -lt $Samples; $i++) {
        Start-Sleep -Milliseconds $IntervalMs
        $current = Get-Process -Id $ProcessId -ErrorAction Stop
        if ($current.StartTime.ToUniversalTime() -ne $started -or $current.Path -ne $exe -or $current.HasExited) {
            throw 'Process exited or identity changed; refusing to sample a recycled PID.'
        }
        $nowCpu = $current.TotalProcessorTime.TotalSeconds
        $nowTime = $watch.Elapsed.TotalSeconds
        $elapsed = $nowTime - $lastTime
        $cpuDelta = $nowCpu - $lastCpu
        if ($elapsed -le 0 -or $cpuDelta -lt 0) { throw 'Invalid monotonic time or CPU counter delta.' }
        $row = [pscustomobject][ordered]@{
            sample = $i + 1; utc = [DateTime]::UtcNow.ToString('o')
            elapsedSeconds = $elapsed; cpuSeconds = $cpuDelta
            cpuMachinePercent = 100.0 * $cpuDelta / $elapsed / $logical
            workingSetBytes = $current.WorkingSet64
            privateBytes = $current.PrivateMemorySize64
            handles = $current.HandleCount; threads = $current.Threads.Count
        }
        $rows.Add($row)
        $row | Export-Csv -LiteralPath $csv -NoTypeInformation -Append -Encoding UTF8
        $lastTime = $nowTime; $lastCpu = $nowCpu
    }
    $summary = [ordered]@{
        schemaVersion = 1; label = $Label; sha256 = $hash; scenario = $Scenario
        samples = $rows.Count; percentileMethod = 'nearest-rank'
        cpuMachinePercentMedian = Percentile @($rows | ForEach-Object { $_.cpuMachinePercent }) 0.5
        cpuMachinePercentP95 = Percentile @($rows | ForEach-Object { $_.cpuMachinePercent }) 0.95
        workingSetBytesMedian = Percentile @($rows | ForEach-Object { $_.workingSetBytes }) 0.5
        workingSetBytesP95 = Percentile @($rows | ForEach-Object { $_.workingSetBytes }) 0.95
        privateBytesMedian = Percentile @($rows | ForEach-Object { $_.privateBytes }) 0.5
        privateBytesP95 = Percentile @($rows | ForEach-Object { $_.privateBytes }) 0.95
    }
    $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding UTF8
    $metadata.status = 'COMPLETED'
} catch {
    $metadata.status = 'FAILED'
    $metadata.error = $_.Exception.Message
    throw
} finally {
    $metadata.actualSamples = $rows.Count
    $metadata.measurementEndUtc = [DateTime]::UtcNow.ToString('o')
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
    $watch.Stop()
}
