$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '../AITaskManagerReadOnly.exe'
$help = & $exe --help
if ($LASTEXITCODE -ne 0 -or -not ($help -match 'read-only|readOnly|One-shot local')) { throw 'CLI help failed' }
foreach ($arguments in @(@('kill','123'),@('snapshot','--force'),@('server'),@('mcp'),@('trim'))) {
    $stdout = & $exe @arguments 2>$null
    if ($LASTEXITCODE -ne 2 -or $stdout) { throw 'Unsupported command was not rejected before output' }
}
$raw = & $exe snapshot
if ($LASTEXITCODE -ne 0) { throw 'Snapshot collection failed in CI' }
$s = $raw | ConvertFrom-Json
if ($s.schemaVersion -ne 1 -or $s.readOnly -ne $true -or $s.kind -ne 'snapshot') { throw 'Invalid snapshot envelope' }
if (-not $s.sampling.complete -or -not $s.sampling.processEnumerationComplete) { throw 'Incomplete own-runner observation' }
if ($s.resources.cpuPercent -ne $null -or $s.resources.gpuAvailable -ne $false) { throw 'Unsupported CLI metrics must not be invented' }
if ($s.sampling.endMs -isnot [string]) { throw '64-bit timestamps must be JSON strings' }
if (@($s.processes).Count -lt 1) { throw 'No process evidence collected' }
foreach ($p in $s.processes) {
    if ($p.identity.pid -isnot [string] -or $p.identity.creationTime -isnot [string]) { throw 'Identity integers lost exact representation' }
    if (-not $p.memorySampleValid -and $p.workingSetMB -ne $null) { throw 'Unavailable memory was turned into zero' }
}
$rawReport = & $exe report
if ($LASTEXITCODE -ne 0) { throw 'Report collection failed in CI' }
$r = $rawReport | ConvertFrom-Json
if ($r.schemaVersion -ne 1 -or $r.readOnly -ne $true -or $r.kind -ne 'findings') { throw 'Invalid report envelope' }
if (-not $r.sampling.complete -or -not $r.sampling.processEnumerationComplete -or $r.sampling.endMs -isnot [string]) { throw 'Report lacks exact sample/completeness metadata' }
if (@($r.findings).Count -ne 8) { throw 'Unexpected deterministic finding set' }
foreach ($id in @('node_oom','port_conflict','gpu_allocation','background_anomaly','hard_faults')) {
    $f = @($r.findings | Where-Object { $_.id -eq $id })
    if ($f.Count -ne 1 -or $f[0].state -ne 'unknown') { throw 'Missing runtime evidence was falsely diagnosed' }
}
# Never print local snapshots/paths or raw reports to CI logs.
Write-Host 'PASS readonly CLI command rejection and JSON snapshot/report integration'
