<#
.SYNOPSIS
    NetGuard Windows 启动脚本（自动检测 Python 解释器）。

.DESCRIPTION
    优先使用环境变量 NETGUARD_PYTHON 指定的解释器，其次项目内
    .venv\Scripts\python.exe，再回退到 py 启动器与 PATH 上的 python。
    要求 Python 3.11+。

.EXAMPLE
    .\scripts\run_netguard.ps1
    .\scripts\run_netguard.ps1 --list-devices
    .\scripts\run_netguard.ps1 --read capture.pcap
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot
$MinVersion = [version]"3.11"

function Test-PythonVersion {
    param([string]$Exe)
    try {
        $raw = & $Exe -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $false }
        return ([version]$raw -ge $MinVersion)
    } catch {
        return $false
    }
}

function Resolve-Python {
    $candidates = @()
    if ($env:NETGUARD_PYTHON) { $candidates += $env:NETGUARD_PYTHON }
    $candidates += (Join-Path $ProjectDir ".venv\Scripts\python.exe")

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate) -and (Test-PythonVersion $candidate)) {
            return $candidate
        }
    }
    foreach ($name in @("py", "python3", "python")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and (Test-PythonVersion $cmd.Source)) {
            return $cmd.Source
        }
    }
    return $null
}

$Python = Resolve-Python
if (-not $Python) {
    Write-Error @"
未找到可用的 Python $MinVersion+ 解释器。

请在项目根目录创建虚拟环境：
  python -m venv .venv
  .\.venv\Scripts\python.exe -m pip install -e .

或临时指定：
  `$env:NETGUARD_PYTHON = "C:\Path\To\python.exe"
"@
    exit 1
}

& $Python (Join-Path $ProjectDir "main.py") @Args
exit $LASTEXITCODE
