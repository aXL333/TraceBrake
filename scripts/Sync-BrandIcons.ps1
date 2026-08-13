[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$resourceDir = Join-Path $repoRoot 'src\Foreman.App\Resources'
$masterPath = Join-Path $resourceDir 'foreman.png'
$browserTargets = @(
    (Join-Path $repoRoot 'extension\icons'),
    (Join-Path $repoRoot 'extension-liveweave\icons')
)
$browserSizes = @(16, 32, 48, 128)
$icoSizes = @(16, 24, 32, 48, 64, 128)

Add-Type -AssemblyName System.Drawing

function New-ResizedBitmap {
    param(
        [Parameter(Mandatory)] [System.Drawing.Image] $Source,
        [Parameter(Mandatory)] [int] $Size
    )

    $bitmap = New-Object System.Drawing.Bitmap(
        $Size,
        $Size,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
        $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.DrawImage($Source, 0, 0, $Size, $Size)
    }
    finally {
        $graphics.Dispose()
    }

    return $bitmap
}

function New-StatusMonocle {
    param(
        [Parameter(Mandatory)] [System.Drawing.Image] $Source,
        [Parameter(Mandatory)] [ValidateSet('Red', 'Amber', 'Green')] [string] $Status
    )

    $bitmap = New-ResizedBitmap -Source $Source -Size 128
    if ($Status -eq 'Red') { return $bitmap }

    # Recolour only saturated red light inside the lens. The metal case, gold trim and chain stay
    # identical across states, preserving one recognisable TraceBrake silhouette at tray size.
    for ($y = 34; $y -le 92; $y++) {
        for ($x = 42; $x -le 100; $x++) {
            $dx = $x - 70
            $dy = $y - 63
            if (($dx * $dx) + ($dy * $dy) -gt 900) { continue }

            $pixel = $bitmap.GetPixel($x, $y)
            if ($pixel.R -lt 38 -or $pixel.R -le ($pixel.G * 1.18) -or $pixel.R -le ($pixel.B * 1.28)) {
                continue
            }

            if ($Status -eq 'Amber') {
                $red = $pixel.R
                $green = [Math]::Min(255, [Math]::Max($pixel.G, [int]($pixel.R * 0.58)))
                $blue = [Math]::Min(255, [int]($pixel.B * 0.72))
            }
            else {
                $red = [Math]::Min(255, [Math]::Max($pixel.B, [int]($pixel.R * 0.20)))
                $green = $pixel.R
                $blue = [Math]::Min(255, [Math]::Max($pixel.B, [int]($pixel.R * 0.25)))
            }

            $bitmap.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($pixel.A, $red, $green, $blue))
        }
    }

    return $bitmap
}

function ConvertTo-IconDibBytes {
    param(
        [Parameter(Mandatory)] [System.Drawing.Image] $Source,
        [Parameter(Mandatory)] [int] $Size
    )

    $bitmap = New-ResizedBitmap -Source $Source -Size $Size
    try {
        $stream = New-Object System.IO.MemoryStream
        $writer = New-Object System.IO.BinaryWriter($stream)
        try {
            $pixelBytes = $Size * $Size * 4
            $maskStride = [int]([Math]::Ceiling($Size / 32.0) * 4)
            $maskBytes = $maskStride * $Size

            # BITMAPINFOHEADER. ICO height includes the colour bitmap plus its 1-bit AND mask.
            $writer.Write([uint32]40)
            $writer.Write([int32]$Size)
            $writer.Write([int32]($Size * 2))
            $writer.Write([uint16]1)
            $writer.Write([uint16]32)
            $writer.Write([uint32]0)
            $writer.Write([uint32]$pixelBytes)
            $writer.Write([int32]0)
            $writer.Write([int32]0)
            $writer.Write([uint32]0)
            $writer.Write([uint32]0)

            # DIB pixels are bottom-up BGRA. The all-zero AND mask defers transparency to alpha.
            for ($y = $Size - 1; $y -ge 0; $y--) {
                for ($x = 0; $x -lt $Size; $x++) {
                    $pixel = $bitmap.GetPixel($x, $y)
                    $writer.Write([byte]$pixel.B)
                    $writer.Write([byte]$pixel.G)
                    $writer.Write([byte]$pixel.R)
                    $writer.Write([byte]$pixel.A)
                }
            }
            $writer.Write((New-Object byte[] $maskBytes))
            $writer.Flush()
            return $stream.ToArray()
        }
        finally {
            $writer.Dispose()
            $stream.Dispose()
        }
    }
    finally {
        $bitmap.Dispose()
    }
}

function Write-MultiSizeIcon {
    param(
        [Parameter(Mandatory)] [System.Drawing.Image] $Source,
        [Parameter(Mandatory)] [string] $Path
    )

    # Use classic 32-bit DIB frames rather than PNG-compressed ICO frames. System.Drawing.Icon—and
    # therefore the tray library—handles DIB frames consistently across supported Windows versions.
    $frames = New-Object 'System.Collections.Generic.List[byte[]]'
    foreach ($size in $icoSizes) {
        $frames.Add((ConvertTo-IconDibBytes -Source $Source -Size $size))
    }

    $file = [System.IO.File]::Create($Path)
    $writer = New-Object System.IO.BinaryWriter($file)
    try {
        $writer.Write([uint16]0)             # reserved
        $writer.Write([uint16]1)             # icon
        $writer.Write([uint16]$frames.Count)

        $offset = 6 + (16 * $frames.Count)
        for ($index = 0; $index -lt $frames.Count; $index++) {
            $size = $icoSizes[$index]
            $frame = $frames[$index]
            $writer.Write([byte]$size)
            $writer.Write([byte]$size)
            $writer.Write([byte]0)           # palette colours
            $writer.Write([byte]0)           # reserved
            $writer.Write([uint16]1)         # colour planes
            $writer.Write([uint16]32)        # bits per pixel
            $writer.Write([uint32]$frame.Length)
            $writer.Write([uint32]$offset)
            $offset += $frame.Length
        }

        foreach ($frame in $frames) { $writer.Write($frame) }
    }
    finally {
        $writer.Dispose()
        $file.Dispose()
    }
}

$master = [System.Drawing.Image]::FromFile($masterPath)
try {
    if ($master.Width -ne 128 -or $master.Height -ne 128) {
        throw "The TraceBrake master icon must be 128 x 128 pixels; found $($master.Width) x $($master.Height)."
    }

    foreach ($target in $browserTargets) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        foreach ($size in $browserSizes) {
            $bitmap = New-ResizedBitmap -Source $master -Size $size
            try {
                $bitmap.Save((Join-Path $target "icon-$size.png"), [System.Drawing.Imaging.ImageFormat]::Png)
            }
            finally {
                $bitmap.Dispose()
            }
        }
    }

    $red = New-StatusMonocle -Source $master -Status Red
    $amber = New-StatusMonocle -Source $master -Status Amber
    $green = New-StatusMonocle -Source $master -Status Green
    try {
        $red.Save((Join-Path $resourceDir 'foreman-red.png'), [System.Drawing.Imaging.ImageFormat]::Png)
        $amber.Save((Join-Path $resourceDir 'foreman-amber.png'), [System.Drawing.Imaging.ImageFormat]::Png)
        $green.Save((Join-Path $resourceDir 'foreman-green.png'), [System.Drawing.Imaging.ImageFormat]::Png)

        Write-MultiSizeIcon -Source $red -Path (Join-Path $resourceDir 'foreman.ico')
        Write-MultiSizeIcon -Source $red -Path (Join-Path $resourceDir 'foreman-red.ico')
        Write-MultiSizeIcon -Source $amber -Path (Join-Path $resourceDir 'foreman-amber.ico')
        Write-MultiSizeIcon -Source $green -Path (Join-Path $resourceDir 'foreman-green.ico')
    }
    finally {
        $red.Dispose()
        $amber.Dispose()
        $green.Dispose()
    }
}
finally {
    $master.Dispose()
}

Write-Host 'Synchronized TraceBrake app, tray and browser-extension icons from the HAL monocle master.'
