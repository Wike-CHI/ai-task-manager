[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$AITaskManagerDirectory,
    [Parameter(Mandatory=$true)][string]$ArgusDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$a = Get-Content -Raw -LiteralPath (Join-Path $AITaskManagerDirectory 'metadata.json') | ConvertFrom-Json
$b = Get-Content -Raw -LiteralPath (Join-Path $ArgusDirectory 'metadata.json') | ConvertFrom-Json
if ($a.status -ne 'COMPLETED' -or $b.status -ne 'COMPLETED') { throw 'Both runs must be complete.' }
if ($a.label -ne 'AITaskManager' -or $b.label -ne 'Argus') { throw 'Run labels do not match the requested comparison.' }
foreach ($field in @('schemaVersion','scenario','osVersion','osBuild','logicalProcessors','totalMemoryBytes','scope','requestedSamples','intervalMs')) {
    if ($a.$field -ne $b.$field) { throw "Mismatched $field; runs are not comparable." }
}
if (($a.cpu -join '|') -ne ($b.cpu -join '|')) { throw 'Different CPU models.' }
$sa = Get-Content -Raw -LiteralPath (Join-Path $AITaskManagerDirectory 'summary.json') | ConvertFrom-Json
$sb = Get-Content -Raw -LiteralPath (Join-Path $ArgusDirectory 'summary.json') | ConvertFrom-Json
foreach ($metric in @('cpuMachinePercentMedian','cpuMachinePercentP95','workingSetBytesMedian','workingSetBytesP95','privateBytesMedian','privateBytesP95')) {
    [pscustomobject]@{ Metric = $metric; AITaskManager = $sa.$metric; Argus = $sb.$metric; Difference = $sa.$metric - $sb.$metric }
}
Write-Verbose "AITaskManager $($a.revision) SHA256=$($a.sha256); Argus $($b.revision) SHA256=$($b.sha256)"
