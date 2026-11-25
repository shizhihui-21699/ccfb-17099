# Exports the exact KnownDLL baseline for the current Windows machine.
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\tools\Export-KnownDlls.ps1 `
#       -OutFile .\known_dlls.txt

[CmdletBinding()]
param(
    [string]$OutFile = "known_dlls.txt"
)

$key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
$item = Get-ItemProperty -Path $key -ErrorAction Stop

$names = $item.PSObject.Properties |
    Where-Object {
        $_.Name -notlike "PS*" -and
        $_.Value -is [string] -and
        -not [string]::IsNullOrWhiteSpace($_.Value)
    } |
    ForEach-Object {
        $value = [string]$_.Value
        if ([System.IO.Path]::GetExtension($value).Length -eq 0) {
            "$value.dll"
        } else {
            $value
        }
    } |
    Sort-Object -Unique

$parent = Split-Path -Parent $OutFile
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$names | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Host "Wrote $($names.Count) KnownDLL names to $OutFile"
