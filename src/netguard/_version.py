"""版本号的单一来源。

单独成模块且不导入任何东西：`pyproject.toml` 通过
`[tool.setuptools.dynamic] version = {attr = "netguard._version.__version__"}`
读取此处，`netguard.__version__` 也转出同一值，避免版本号出现第二份拷贝。
"""

__version__ = "0.3.0"
