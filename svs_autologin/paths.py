"""数据目录解析(阶段 5):把「数据放哪」从各文件的硬编码里收敛到一处。

三级解析,优先级从高到低:

1. ``SVS_DATA_DIR`` 环境变量 —— 开发/测试重定向(阶段 5 验收门就靠它);
2. ``<程序根>/.installed`` 标记文件(内容 = 数据目录绝对路径,安装器写)
   —— 分发版;
3. 仓库根 —— 开发回退,**必须与阶段 2-4 的现状逐字节一致**
   (intercept_addon 现在就是 ``_REPO_ROOT / "config.local.json"``)。

``confdir()`` 特殊:开发模式维持 ``~/.mitmproxy``(mitmproxy 默认,现有
dev CA 零迁移);只要数据目录被显式指定(env 或安装标记),confdir 就落在
数据目录下 —— 分发版用每台机器自己的 CA(docs/constraints.md C3),
绝不共享 ~/.mitmproxy。

纯解析,不建目录、不写文件 —— 创建是调用方的事(save_accounts 自己
mkdir,日志 handler 挂载前自己 mkdir)。刻意不做缓存:每次调用只是
一次 env 查表 + 至多一次 stat,而缓存会让 monkeypatch 环境变量的测试
出现失效顺序问题。
"""

from __future__ import annotations

import os
from pathlib import Path

#: 数据目录环境变量(开发/测试重定向用)。
DATA_DIR_ENV = "SVS_DATA_DIR"

#: 安装标记文件名(内容 = 数据目录绝对路径,由 install.ps1 原子写入)。
INSTALLED_MARKER = ".installed"

# svs_autologin/ 的上一级 = 仓库根(开发)或安装根(分发布局同形:
# dist/svs-autologin/<ver>/{runtime/, svs_autologin/, tools/, ...})。
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _marker_data_dir(base: Path) -> Path | None:
    """``<base>/.installed`` 里写的绝对路径;缺失/空内容/不可读 → None。

    空内容 = 半途安装:宁可回退开发形态,也不把数据写进空字符串目录。
    """
    marker = base / INSTALLED_MARKER
    try:
        content = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return Path(content) if content else None


def _explicit_data_dir() -> Path | None:
    """env > 安装标记;都没有 → None(调用方走开发回退)。

    env 给相对路径时按当前工作目录 absolutize(与 mitmdump ``--set
    confdir=`` 的处理一致);标记文件内容为空(半途安装)视同未安装。
    """
    env = os.environ.get(DATA_DIR_ENV, "").strip()
    if env:
        return Path(os.path.abspath(os.path.expanduser(env)))
    return _marker_data_dir(_REPO_ROOT)


def data_dir() -> Path:
    """数据目录(绝对路径)。"""
    return _explicit_data_dir() or _REPO_ROOT


def is_dev() -> bool:
    """True = 未安装、未重定向(仓库根 + ~/.mitmproxy 的开发形态)。"""
    return _explicit_data_dir() is None


def is_uninstalled_distribution(root: Path | None = None) -> bool:
    """打包形态(带 ``runtime\\``)但还没有安装标记 —— 用户还没跑 setup.bat。

    2026-10-23 的现场:把 zip 解压出来直接双击 ``svs-autologin.exe``,
    GUI 以开发回退形态运行(数据目录 = 解压目录,没有 config.local.json),
    代理一启动就因缺配置崩溃,用户只看到「代理进程启动失败」。

    判据刻意收得很窄,避免对开发者误报:

    * ``SVS_DATA_DIR`` 已设置 → False(显式重定向,测试/开发形态);
    * ``.installed`` 已存在 → False(装过了);
    * ``<root>\\runtime\\python.exe`` 存在 → 说明这是**打包产物**而不是源码
      仓库(仓库里没有 runtime\\),可以断言用户是想运行它。

    纯函数式判断,不建目录、不写文件;``root`` 只为测试注入。
    """
    if os.environ.get(DATA_DIR_ENV, "").strip():
        return False
    base = Path(root) if root is not None else _REPO_ROOT
    if _marker_data_dir(base) is not None:
        return False
    return (base / "runtime" / "python.exe").exists()


def config_path(base: Path | None = None) -> Path:
    """``<数据目录>/config.local.json``;``base`` 给定时从它派生(注入隔离用,
    AppModel/测试不再各自手抄派生式 —— 改名只改这里)。"""
    return (Path(base) if base is not None else data_dir()) / "config.local.json"


def accounts_path(base: Path | None = None) -> Path:
    return (Path(base) if base is not None else data_dir()) / "accounts.json"


def log_dir(base: Path | None = None) -> Path:
    return (Path(base) if base is not None else data_dir()) / "log"


def pid_file(base: Path | None = None) -> Path:
    return (Path(base) if base is not None else data_dir()) / "proxy.pid"


def export_dir() -> Path:
    return data_dir() / "export"


def confdir() -> Path:
    """mitmproxy confdir(CA 所在)。

    开发模式 = ``~/.mitmproxy``(阶段 0-4 的 CA 继续用,零迁移);
    显式数据目录 = ``<data>/certs``(分发版自己的 CA,gen_ca.py 预生成)。
    """
    explicit = _explicit_data_dir()
    if explicit is None:
        return Path.home() / ".mitmproxy"
    return explicit / "certs"
