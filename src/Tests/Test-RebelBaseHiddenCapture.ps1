param(
    [Parameter(Mandatory)][string]$Baseline,
    [Parameter(Mandatory)][string]$EngineDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$Baseline = [IO.Path]::GetFullPath($Baseline)
$EngineDirectory = [IO.Path]::GetFullPath($EngineDirectory)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new output directory.' }
if ($OutputDirectory.StartsWith($Baseline.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Output cannot be inside the retail baseline.' }
$resourceNames = @('resource/JKMRES.GOO','resource/jk_.cd','resource/JKMsndLO.goo','episode/JKM.GOO')
$binaryNames = @('openjkdf2-64.exe','OpenAL32.dll','libGameNetworkingSockets.dll')
$sources = foreach ($name in $resourceNames) {
    $path = Join-Path $Baseline $name
    $item = Get-Item -LiteralPath $path
    [ordered]@{ relativePath=$name; source=$path; bytes=$item.Length; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$binaries = foreach ($name in $binaryNames) {
    $path = Join-Path $EngineDirectory $name
    $item = Get-Item -LiteralPath $path
    [ordered]@{ relativePath=$name; source=$path; bytes=$item.Length; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
foreach ($source in @($sources) + @($binaries)) {
    $target = Join-Path $OutputDirectory $source.relativePath
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force | Out-Null
    Copy-Item -LiteralPath $source.source -Destination $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $source.sha256) { throw 'Staged input differs.' }
}
[IO.File]::WriteAllText((Join-Path $OutputDirectory '.openjkdf2-capture-session'), "isolated-original-mots-inspection`n")
$image = Join-Path $OutputDirectory 'rebelbase.ppm'
$request = Join-Path $OutputDirectory 'capture-request.txt'
# SED's 75 degrees is vertical. rdCamera's requested field is horizontal here.
$horizontalFov = (2*[Math]::Atan([Math]::Tan(75*[Math]::PI/360)*1.5)*180/[Math]::PI).ToString('R',[Globalization.CultureInfo]::InvariantCulture)
$requestText = "sed-engine-capture-v1`n960 640 80 3 30000`n-5.19905 5.10426 3.003014 0 180 0 $horizontalFov`n$image`n"
[IO.File]::WriteAllText($request,$requestText,[Text.UTF8Encoding]::new($false))
# Inspect only windows owned by the spawned process. No titles, pixels, or other
# user applications are inspected or controlled.
if (-not ('CaptureOwnedWindows' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CaptureOwnedWindows {
    delegate bool EnumProc(IntPtr window, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr data);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    public static int[] Inspect(uint process) {
        int all=0,visible=0,foreground=0; IntPtr focused=GetForegroundWindow();
        EnumWindows((w,d)=> { uint pid; GetWindowThreadProcessId(w,out pid); if(pid==process) { all++; if(IsWindowVisible(w)) visible++; if(w==focused) foreground++; } return true; },IntPtr.Zero);
        return new[]{all,visible,foreground};
    }
}
'@
}
$oldRequest = $env:OPENJKDF2_CAPTURE_REQUEST
$env:OPENJKDF2_CAPTURE_REQUEST = $request
$stdout = Join-Path $OutputDirectory 'stdout.log'
$stderr = Join-Path $OutputDirectory 'stderr.log'
$samples = 0; $maxWindows = 0; $maxVisible = 0; $maxForeground = 0; $timeout = $false
$clock = [Diagnostics.Stopwatch]::StartNew()
try {
    $child = Start-Process -FilePath (Join-Path $OutputDirectory 'openjkdf2-64.exe') -ArgumentList @('-capture','-autostart','-sp','-motsCompat','-noHUD','-episode','JKM','-map','s1l1_rebelbase.jkl') -WorkingDirectory $OutputDirectory -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    while (-not $child.HasExited) {
        $owned = [CaptureOwnedWindows]::Inspect([uint32]$child.Id)
        $samples++; $maxWindows=[Math]::Max($maxWindows,$owned[0]); $maxVisible=[Math]::Max($maxVisible,$owned[1]); $maxForeground=[Math]::Max($maxForeground,$owned[2])
        if ($owned[1] -gt 0 -or $owned[2] -gt 0) { Stop-Process -Id $child.Id -Force; throw 'Owned child exposed a visible/focused window; stopped immediately.' }
        if ($clock.Elapsed.TotalSeconds -gt 45) { $timeout=$true; Stop-Process -Id $child.Id -Force; break }
        Start-Sleep -Milliseconds 100
        $child.Refresh()
    }
    $child.WaitForExit()
} finally {
    $clock.Stop()
    $env:OPENJKDF2_CAPTURE_REQUEST = $oldRequest
}
$resourceVerification = foreach ($source in $sources) {
    $stagedHash = (Get-FileHash -LiteralPath (Join-Path $OutputDirectory $source.relativePath) -Algorithm SHA256).Hash.ToLowerInvariant()
    $sourceHash = (Get-FileHash -LiteralPath $source.source -Algorithm SHA256).Hash.ToLowerInvariant()
    [ordered]@{ relativePath=$source.relativePath; beforeSha256=$source.sha256; baselineAfterSha256=$sourceHash; stagedAfterSha256=$stagedHash; unchanged=($stagedHash -eq $source.sha256 -and $sourceHash -eq $source.sha256) }
}
$receiptPath = "$image.json"
$validImage = $false
if (Test-Path -LiteralPath $image) {
    $bytes=[IO.File]::ReadAllBytes($image); $header=[Text.Encoding]::ASCII.GetBytes("P6`n960 640`n255`n")
    $validImage=$bytes.Length -eq $header.Length+960*640*3
    for($i=0;$validImage -and $i -lt $header.Length;$i++){ if($bytes[$i] -ne $header[$i]){$validImage=$false} }
}
$engineReceipt = if(Test-Path -LiteralPath $receiptPath){Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json}else{$null}
$record=[ordered]@{
    schemaVersion=1; command=@('-capture','-autostart','-sp','-motsCompat','-noHUD','-episode','JKM','-map','s1l1_rebelbase.jkl')
    processExitCode=$child.ExitCode; timedOut=$timeout; elapsedSeconds=$clock.Elapsed.TotalSeconds
    windowObservation=[ordered]@{samples=$samples;maximumOwnedWindows=$maxWindows;maximumVisibleOwnedWindows=$maxVisible;maximumForegroundOwnedWindows=$maxForeground;pollMilliseconds=100;transientWindowsBetweenSamplesNotExcluded=$true}
    requestSha256=(Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant()
    binaries=$binaries;resources=$resourceVerification;validPpm=$validImage;engineReceipt=$engineReceipt
    imageSha256= $(if($validImage){(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null})
    pixelParityClaimed=$false; simulationDeterministic=$false
}
$record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'launcher-receipt.json') -Encoding utf8NoBOM
if($timeout -or $child.ExitCode -ne 0 -or -not $validImage -or $null -eq $engineReceipt -or ($resourceVerification | Where-Object {-not $_.unchanged})) { throw "Capture did not complete; see $OutputDirectory" }
$record | ConvertTo-Json -Depth 10
