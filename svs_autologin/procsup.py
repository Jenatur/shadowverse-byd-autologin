"""代理进程支撑(阶段 5):命令构造、就绪探测、停止。

GUI 与代理的进程契约(计划「进程模型」节):

* GUI 用 ``subprocess.Popen`` detached 拉起代理 —— 代理独立于 GUI 存活
  是硬需求(SDK 轮询断连不重试,代理必须常驻);
* 停止按 pidfile 记录的 PID taskkill;**绝不杀未知进程**(443 被别人占
  → PORT_BUSY 提示用户,不是替用户动手);
* 就绪探测 = ``connect_ex`` 回环连接(禁式清单里没有它,语义上也不是
  HTTP 客户端)。

全部可注入:spawner(替代真 Popen)、prober(替代真端口探测)、killer
(替代真 taskkill)—— 测试在 conftest 的 no_network 断网保护下用桩,
逻辑层自身零网络、零进程。
"""

from __future__ import annotations

import logging
import subprocess
import socket
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

log = logging.getLogger(__name__)

#: 子进程不弹控制台窗(GUI pythonw 下也不闪黑框)。
CREATE_NO_WINDOW = 0x08000000

#: 就绪探测参数:0.5s 一次,最长 30s(mitmdump 冷启 import 慢,dev 启动脚本
#: 的 10s 实测偏紧;低配机再往上调是用户可感知的等待,30s 是折中)。
PROBE_INTERVAL = 0.5
READY_TIMEOUT = 30.0

#: taskkill 的等待上限:超过这个进程还没死,就是真的杀不动了。
KILL_TIMEOUT = 10.0

#: mitm-*.log 保留份数(计划§4):每次代理生命周期一份,超过就删最旧的。
MITM_LOG_KEEP = 5


def prune_mitm_logs(log_dir: Path, keep: int = MITM_LOG_KEEP) -> None:
    """把 ``log_dir`` 里的 mitm-*.log 删到只剩最新 ``keep`` 份。

    每次代理生命周期一个文件、不轮转 —— 没有清理就是无限增长(审查
    Spec-1)。删失败(占用/权限)静默跳过:清理是尽力而为,不能阻塞启动。
    """
    try:
        logs = sorted(log_dir.glob("mitm-*.log"))
    except OSError:
        return
    for old in logs[:-keep] if keep > 0 else logs:
        try:
            old.unlink()
        except OSError:
            pass


def build_proxy_command(
    python_exe: str,
    run_mitmdump: str,
    port: int = 443,
    *,
    record_only: bool = False,
) -> List[str]:
    """代理进程的完整命令行(纯函数)。

    ``record_only`` 走 run_mitmdump 的 mode 参数(它自己设
    SVS_RECORD_ONLY)—— 模式开关不经过配置文件:配置文件记录的是用户的
    **长期选择**(auto 指向),进程模式是**当下动作**,混在一起会在崩溃
    时留下被清空的 auto。
    """
    argv = [python_exe, run_mitmdump, str(port)]
    if record_only:
        argv.append("record")
    return argv


def spawn_proxy(
    command: List[str],
    *,
    mitm_log_dir: Optional[Path] = None,
    spawner: Optional[Callable[..., subprocess.Popen]] = None,
) -> Tuple[subprocess.Popen, Optional[Path]]:
    """detached 拉起代理,返回 (Popen, 日志路径)。

    ``mitm_log_dir`` 给定时,stdout/stderr 重定向到其下的
    mitm-<时间戳>.log(每次代理生命周期一份);None = 不重定向
    (开发调试要看控制台)。
    """
    log_path: Optional[Path] = None
    if mitm_log_dir is not None:
        mitm_log_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        log_path = mitm_log_dir / f"mitm-{stamp}.log"
        sink = open(log_path, "ab")
        prune_mitm_logs(mitm_log_dir)
    else:
        sink = None

    popen = spawner or subprocess.Popen
    try:
        proc = popen(
            command,
            stdout=sink,
            stderr=subprocess.STDOUT if sink else None,
            stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
    finally:
        if sink is not None:
            sink.close()  # 子进程已拿到句柄的副本;父进程这边可以关
    log.info("代理进程已拉起:%s(pid=%s, log=%s)", command[0], proc.pid, log_path)
    return proc, log_path


def is_ready(port: int, prober: Optional[Callable[[int], bool]] = None) -> bool:
    """端口是否已有监听(回环 connect_ex,一次)。"""
    if prober is not None:
        return prober(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def wait_ready(
    *,
    alive: Callable[[], bool],
    port: int = 443,
    timeout: float = READY_TIMEOUT,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    prober: Optional[Callable[[int], bool]] = None,
) -> str:
    """等代理就绪;返回 'ready' / 'crashed' / 'timeout'。

    ``alive()`` 是进程存活检查(注入;真实现是 ``poll() is None``)。
    区分三种终态给用户不同的提示,不在这层决定怎么办 —— 那是 GUI 的事。
    """
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if not alive():
            return "crashed"
        if is_ready(port, prober):
            return "ready"
        sleep(PROBE_INTERVAL)
    return "timeout"


def stop_proxy(pid: int, killer: Optional[Callable[[int], None]] = None) -> None:
    """按 PID 停止代理(taskkill /T /F:连子进程树一起,与 dev 工作流同语义)。

    代理没有需要刷盘的内存态(账号落盘是原子事务),强杀安全 —— 这已被
    阶段 2-4 的验证行为背书(每次 dev 停代理都是 Stop-Process -Force)。
    """
    if killer is not None:
        killer(pid)
        return
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        timeout=KILL_TIMEOUT,
        check=False,
    )
    log.info("代理进程已停止(pid=%s)", pid)


def launch_game(exe: str) -> Optional[subprocess.Popen]:
    """启动游戏(GUI 启动按钮的最后一步;计划§5「起游戏」)。

    已知怪癖(findings 实录):旧实例还活着时新启动**静默无进程** ——
    所以调用方应先确保旧实例已关。启动失败返回 None(GUI 提示),不抛。
    """
    try:
        proc = subprocess.Popen(
            [exe],
            cwd=str(Path(exe).parent),
            stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError as exc:
        log.error("游戏启动失败:%s(%s)", exe, exc)
        return None
    log.info("游戏已启动:%s(pid=%s)", exe, proc.pid)
    return proc


def find_game_processes(image_dir: Optional[str]) -> List[int]:
    """游戏已运行?返回其 PID 列表(按主映像目录匹配;没配路径返回空)。

    添加账号前的「一键关游戏」与启动前的「跳过已运行」都要它。用
    PowerShell 而不是 psutil:进程枚举是本地只读,不值得为此进依赖。
    """
    if not image_dir:
        return []
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Process | Where-Object { $_.Path -like '" + image_dir.replace("'", "''") + "*' } "
             "| Select-Object -ExpandProperty Id)"],
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [int(ln) for ln in out.stdout.decode("utf-8", errors="replace").split() if ln.strip().isdigit()]
