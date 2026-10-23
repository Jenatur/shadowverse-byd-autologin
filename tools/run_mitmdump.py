r"""以编程方式拉起 mitmdump,绕开这套 embed 解释器里坏掉的 console 入口。

用法::

    python.exe tools\run_mitmdump.py                 # 443, normal
    python.exe tools\run_mitmdump.py 4439            # 测试端口
    python.exe tools\run_mitmdump.py 443 record      # 记录模式(添加账号)

动机(2026-10-12 实测):``python -m mitmproxy.tools.dump`` 与
``Scripts\mitmdump.exe`` 在 embed 环境里**静默退出**——连 ``--version``
都空跑、零输出、退出码 0。同一解释器下 ``mitmproxy.tools.main.mitmdump()``
可以正常调用(它才是真正的入口:解析参数 → run() → asyncio 跑起来),
坏的只是 console_scripts 那层壳。本文件伪造 ``sys.argv`` 直接调它。

参数与阶段 2 实测形态一致(开发侧取证记录):reverse 到 mkey 的
CNAME 别名 + keep_host_header。``connection_strategy=lazy`` 消掉上游证书
hostname 警告(纯噪音,不影响转发)。

阶段 5 变更:

* ``-s`` 指向同目录 ``intercept_addon.py`` 的绝对路径 —— 分发版 GUI 从
  任意 CWD 拉起,不再要求「必须从仓库根启动」(2026-10-16 修正:一度
  写成 ``__file__`` 指向本文件自身,代理退化成纯转发,记录/自动登录
  全部静默失效);
* ``--set confdir`` 来自 paths.confdir():开发形态维持 ~/.mitmproxy
  (现有 CA 零迁移),安装形态指 <数据目录>\\certs;
* ``record`` 模式设置 SVS_RECORD_ONLY=1(intercept_addon.load 消费):
  auto 表视为空 → 手工扫码路径自动落盘账号,不起拨号。
"""

from __future__ import annotations

import os
import pathlib
import sys

from mitmproxy.tools.main import mitmdump

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from svs_autologin import paths  # noqa: E402
from svs_autologin.logging_setup import attach_file_handler  # noqa: E402

#: intercept_addon.load() 消费的记录模式开关(名字以那边为准)。
RECORD_ONLY_ENV = "SVS_RECORD_ONLY"

MODES = ("normal", "record")


def build_argv(port: str, mode: str) -> list[str]:
    """构造 mitmdump 的 sys.argv(纯函数,测试直接咬)。"""
    return [
        "mitmdump",
        "--mode", "reverse:https://mpay-cn.ntes53.netease.com:443",
        "--listen-host", "127.0.0.1",
        "--listen-port", port,
        "--set", "keep_host_header=true",
        "--set", "connection_strategy=lazy",
        "--set", "flow_detail=1",
        "--set", f"confdir={paths.confdir()}",
        "-s", str(pathlib.Path(__file__).resolve().parent / "intercept_addon.py"),
    ]


def main() -> int:
    port = sys.argv[1] if len(sys.argv) > 1 else "443"
    mode = sys.argv[2] if len(sys.argv) > 2 else "normal"
    if mode not in MODES:
        print(f"unknown mode: {mode!r} (expected one of {MODES})", file=sys.stderr)
        return 2
    if mode == "record":
        os.environ[RECORD_ONLY_ENV] = "1"
    # 代理进程自己的日志:<data>/log/proxy.log(addon + InterceptRules 的
    # logging 输出全走这里;mitmdump 的 stdout 由 GUI 重定向到
    # 单独的 mitm-*.log)。attach 而非 configure:mitmdump 进程的根
    # logger 上有它自己的 handler,不能清。
    attach_file_handler(str(paths.log_dir() / "proxy.log"))
    sys.argv = build_argv(port, mode)
    mitmdump()
    return 0


if __name__ == "__main__":
    sys.exit(main())
