<#
.SYNOPSIS
    NetGuard Windows 启动脚本。

.DESCRIPTION
    薄封装：只负责找到一个能运行 scripts/launch.py 的 Python，然后原样转交参数。
    解释器优先级（NETGUARD_PYTHON → 项目内 .venv → PATH）、Python 版本下限校验
    与环境自检都由 launch.py 完成，避免在多个脚本里重复版本判断。

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
$Launch = Join-Path $ProjectDir "scripts\launch.py"

if (-not (Test-Path $Launch)) {
    Write-Error "未找到 $Launch，请确认仓库结构完整。"
    exit 1
}

function Resolve-Python {
    $candidates = @()
    if ($env:NETGUARD_PYTHON) { $candidates += $env:NETGUARD_PYTHON }
    $candidates += (Join-Path $ProjectDir ".venv\Scripts\python.exe")

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    foreach ($name in @("py", "python3", "python")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

$Python = Resolve-Python
if (-not $Python) {
    Write-Error @"
未找到任何 Python 解释器。

请安装 Python 3.11+ 后重试，或在项目根目录创建虚拟环境：
  python -m venv .venv
  .\.venv\Scripts\python.exe -m pip install -e .

或临时指定：
  `$env:NETGUARD_PYTHON = "C:\Path\To\python.exe"
"@
    exit 1
}

& $Python $Launch @Args
exit $LASTEXITCODE
