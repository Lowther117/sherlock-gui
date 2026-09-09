# ensure_python.ps1 - find a REAL Python 3.9+ with tkinter, or install one.
# Prints exactly one line to stdout on success: the full path to python.exe.
# Everything else goes to the console via Write-Host (not captured by callers).
#
# Usage from a .bat:
#   for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure_python.ps1"`) do set "PY=%%P"

$ErrorActionPreference = "SilentlyContinue"
$MinMajor = 3; $MinMinor = 9
$Probe = "import sys, tkinter; sys.stdout.write(sys.executable + '|' + str(sys.version_info[0]) + '.' + str(sys.version_info[1]) + '|' + str(tkinter.TkVersion))"

function Test-Py($exe) {
    if (-not $exe) { return $null }
    if ($exe -like "*\WindowsApps\*") { return $null }      # Microsoft Store stub
    if (-not (Test-Path -LiteralPath $exe)) { return $null }
    try {
        $out = & $exe -c $Probe 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $parts = ($out | Select-Object -Last 1).Split("|")
        if ($parts.Count -lt 3) { return $null }
        $v = $parts[1].Split(".")
        if ([int]$v[0] -lt $MinMajor -or ([int]$v[0] -eq $MinMajor -and [int]$v[1] -lt $MinMinor)) { return $null }
        if ([double]$parts[2] -lt 8.6) { return $null }
        return $parts[0]
    } catch { return $null }
}

function Find-Py {
    $cands = @()
    # py launcher
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        foreach ($ver in @("-3.13", "-3.12", "-3.11", "-3.10", "-3.9", "-3")) {
            $p = & $py.Source $ver -c "import sys; sys.stdout.write(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $p) { $cands += $p }
        }
    }
    # PATH
    foreach ($n in @("python.exe", "python3.exe")) {
        foreach ($c in (Get-Command $n -All -ErrorAction SilentlyContinue)) { $cands += $c.Source }
    }
    # known install dirs
    $roots = @("$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "C:\")
    foreach ($r in $roots) {
        if ($r -and (Test-Path $r)) {
            Get-ChildItem -Path $r -Directory -Filter "Python3*" -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | ForEach-Object { $cands += (Join-Path $_.FullName "python.exe") }
        }
    }
    foreach ($c in ($cands | Select-Object -Unique)) {
        $ok = Test-Py $c
        if ($ok) { return $ok }
    }
    return $null
}

function Refresh-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
}

$found = Find-Py
if ($found) { Write-Output $found; exit 0 }

Write-Host "No usable Python 3.9+ found - installing Python 3.12 (this is a one-off)..."

# 1. winget
$winget = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($winget) {
    Write-Host "  trying winget..."
    & $winget.Source install -e --id Python.Python.3.12 --scope user --silent `
        --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
    Refresh-Path
    $found = Find-Py
    if ($found) { Write-Output $found; exit 0 }
    Write-Host "  winget did not produce a usable Python (source blocked or install failed)."
}

# 2. python.org installer
$ver = "3.12.10"
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "" }
$file = if ($arch) { "python-$ver-$arch.exe" } else { "python-$ver.exe" }
$url = "https://www.python.org/ftp/python/$ver/$file"
$dst = Join-Path $env:TEMP $file
Write-Host "  downloading $url ..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing
} catch {
    Write-Host "  download failed: $_"
}
if (Test-Path $dst) {
    Write-Host "  running installer silently (per-user, with tkinter and the py launcher)..."
    $p = Start-Process -FilePath $dst -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1 Include_tcltk=1 Include_launcher=1 Include_test=0 Include_doc=0" -Wait -PassThru
    Write-Host "  installer exit code: $($p.ExitCode)"
    Refresh-Path
    $found = Find-Py
    if ($found) { Write-Output $found; exit 0 }
}

Write-Host "Could not find or install Python. Install Python 3.12 from https://www.python.org/downloads/windows/ (tick 'tcl/tk') and run this again."
exit 1
