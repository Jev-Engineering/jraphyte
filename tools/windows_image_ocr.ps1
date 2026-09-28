param(
    [Parameter(Mandatory = $true)][string]$CropPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)
# Existing Windows OCR only. No download, service, credential or network call.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility') -ErrorAction Stop
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null

function Await-WinRT($Operation, [Type]$ResultType) {
    $method = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    $task = $method.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    if (-not $task.Wait(120000)) { throw 'local_ocr_timeout' }
    return $task.Result
}

function Get-OcrIdentity {
    $dll = Get-Item -LiteralPath (Join-Path $env:WINDIR 'System32\Windows.Media.Ocr.dll')
    $resources = @{}
    $resourceRoot = Join-Path $env:WINDIR 'OCR'
    foreach ($file in Get-ChildItem -LiteralPath $resourceRoot -Recurse -File) {
        $relative = $file.FullName.Substring($resourceRoot.Length + 1).Replace('\', '/')
        $resources[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return @{
        engine_dll_sha256 = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        engine_file_version = $dll.VersionInfo.FileVersion
        installed_ocr_resource_sha256 = $resources
        operating_system_build = [Environment]::OSVersion.Version.ToString()
        model_revision_interface = 'Windows.Media.Ocr exposes component version, not a separate model revision'
    }
}

$cropFile = (Get-Item -LiteralPath $CropPath).FullName
$cropHash = (Get-FileHash -LiteralPath $cropFile -Algorithm SHA256).Hash.ToLowerInvariant()
$identity = Get-OcrIdentity
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($null -eq $engine) { throw 'installed_local_ocr_language_unavailable' }
$file = Await-WinRT ([Windows.Storage.StorageFile]::GetFileFromPathAsync($cropFile)) ([Windows.Storage.StorageFile])
$stream = Await-WinRT ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
try {
    $decoder = Await-WinRT ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bitmap = Await-WinRT ($decoder.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
        [Windows.Graphics.Imaging.BitmapAlphaMode]::Ignore)) ([Windows.Graphics.Imaging.SoftwareBitmap])
    try {
        if ($bitmap.PixelWidth -gt [Windows.Media.Ocr.OcrEngine]::MaxImageDimension -or
            $bitmap.PixelHeight -gt [Windows.Media.Ocr.OcrEngine]::MaxImageDimension) { throw 'local_ocr_image_budget' }
        $result = Await-WinRT ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
        $lines = @($result.Lines | ForEach-Object {
            @{ text = $_.Text; words = @($_.Words | ForEach-Object {
                @{ text = $_.Text; box = @($_.BoundingRect.X, $_.BoundingRect.Y, $_.BoundingRect.Width, $_.BoundingRect.Height);
                   location_basis = 'model-estimate-crop-pixels' }
            }) }
        })
        $configuration = @{ component = $identity; language = $engine.RecognizerLanguage.LanguageTag;
            max_image_dimension = [Windows.Media.Ocr.OcrEngine]::MaxImageDimension;
            pixel_format = 'Bgra8'; alpha_mode = 'Ignore'; local_only = $true;
            implementation_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() }
        # Raw output retains model-estimated locations; candidate source geometry
        # comes only from the original PDF render and reviewer-selected crop.
        $payload = @{ version = 'windows-local-image-ocr-v1'; engine = 'Windows.Media.Ocr';
            revision = $identity.engine_dll_sha256; configuration = $configuration;
            input_crop_sha256 = $cropHash; output_status = 'complete';
            text = ($lines | ForEach-Object { $_.text }) -join "`n";
            text_angle = $result.TextAngle; lines = $lines }
        $after = Get-OcrIdentity
        if ((Get-FileHash -LiteralPath $cropFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $cropHash -or
            ($identity | ConvertTo-Json -Depth 10 -Compress) -ne ($after | ConvertTo-Json -Depth 10 -Compress)) {
            throw 'local_ocr_input_or_component_changed'
        }
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($payload | ConvertTo-Json -Depth 20) + "`n")
        $output = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        try { $output.Write($bytes, 0, $bytes.Length); $output.Flush($true) } finally { $output.Dispose() }
        @{ status = 'LOCAL_OCR_COMPLETE'; characters = $payload.text.Length; lines = $lines.Count } | ConvertTo-Json -Compress
    } finally { $bitmap.Dispose() }
} finally { $stream.Dispose() }
