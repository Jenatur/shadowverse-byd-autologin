"""GUI 应用模型(阶段 5):代理进程状态机 + 账号表观察。

设计(计划「进程模型」「记录模式」节):

* 状态机把 GUI 能做的每件事变成显式迁移,非法迁移抛错 —— GUI 按钮的
  可用性直接映射状态,用户点不出未定义的组合;
* 代理进程按 pidfile 管理:启动写 PID,新 GUI 实例靠 pidfile + 端口探测
  **收养**在跑的代理(代理独立于 GUI 存活是硬需求);443 被别人的进程占
  但 pidfile 里没有 → PORT_BUSY,**绝不杀未知进程**;
* 就绪等待是**同步快路径 + 异步慢路径**:adopt_or_start 在 30s 内等到
  就绪就直接给结果;超时(进程活着但没监听)不是失败 —— bind 失败的
  mitmdump 会直接退出(= CRASHED),活着不监听只可能是冷启慢,状态保持
  STARTING,由 poll() 继续盯到就绪;
* 添加账号 = 起 record 模式代理(auto 视为空,手工扫码落盘)+
  AccountsWatcher 轮询**解析后的记录集**。mtime 与文件长度都不可靠
  (upsert 会原地替换旧记录;save_accounts 的原子写保证读到的是完整
  文件),diff 必须在记录语义层面做。

config / accounts / pidfile 路径经 ``paths`` 的同名函数派生(``base=``
注入的 data_dir)—— 派生式只有一份,AppModel 的测试靠 data_dir 注入
隔离,不会碰真实数据目录。

零 Qt、零网络、零进程:spawner/killer/prober/时钟全部可注入。
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from svs_autologin import paths, procsup
from svs_autologin.accounts import Account, load_accounts

log = logging.getLogger(__name__)

#: 状态机状态。
IDLE = "idle"
STARTING = "starting"
RUNNING = "running"
NEEDS_RESTART = "needs_restart"
ADD_ACCOUNT = "add_account"
STOPPING = "stopping"
PORT_BUSY = "port_busy"
CRASHED = "crashed"

#: 合法状态迁移表。没有自环(自环 = 允许"什么都没发生"伪装成事件),
#: 唯一例外 PORT_BUSY→PORT_BUSY:重试后仍被占是真实的探测结果。
_LEGAL: Dict[str, set] = {
    # RUNNING = 收养(pidfile 有记录且端口通,没经过 STARTING)
    IDLE: {STARTING, PORT_BUSY, RUNNING},
    # STOPPING = spawn 抛异常后的停机回收;超时不迁移(留在 STARTING 给 poll)
    STARTING: {RUNNING, ADD_ACCOUNT, CRASHED, PORT_BUSY, STOPPING},
    RUNNING: {NEEDS_RESTART, STOPPING, ADD_ACCOUNT, CRASHED},
    # 变更后的唯一出路是停(停完由 restart()/adopt_or_start() 重新走启动)
    NEEDS_RESTART: {STOPPING},
    # 结束添加 = 停记录代理(起正常代理是 GUI 随后调 adopt_or_start 的新循环)
    ADD_ACCOUNT: {STOPPING},
    STOPPING: {IDLE},
    PORT_BUSY: {STARTING, PORT_BUSY},
    CRASHED: {STARTING, PORT_BUSY},
}

#: AccountsWatcher 的轮询间隔(秒)。手机扫码 → exchange 落盘是分钟级
#: 事件,1s 的观察延迟对用户体验无感。
WATCH_INTERVAL = 1.0


def config_fingerprint(path: Path) -> Optional[Tuple[float, int]]:
    """config.local.json 的 (mtime, size);不存在返回 None。

    代理启动时记一份,GUI 周期比对 → 不一致且 RUNNING = NEEDS_RESTART
    (GUI 设置页改配置、用户手工改文件,都能被看见)。
    """
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime, st.st_size)


def _account_sig(account: Account) -> Tuple[Any, ...]:
    """一条记录的观察签名:uuid 相同时,这三元组变了才算「账号变化」。

    刻意**不含** name —— rename 是纯 UI 操作,不该触发「检测到新账号」。
    """
    return (
        account.user_info.get("id", ""),
        account.user_info.get("token", ""),
        account.last_login_time,
    )


class AccountChange:
    """AccountsWatcher 检出的一条变化:新记录,或既有记录的更新。"""

    def __init__(self, account: Account, kind: str) -> None:
        self.account = account
        self.kind = kind  # 'new' / 'updated'


class AccountsWatcher:
    """轮询 accounts.json 的**解析后记录集**,按 uuid diff。

    识别:新 uuid → 'new';既有 uuid 但签名变了 → 'updated'(重新扫码
    upsert 就地换凭据)。一次 poll 有多条变化时只报 **last_login_time
    最大的**那条(多条 = 之前漏拍,最新的才是用户刚扫的码)。
    """

    def __init__(self, accounts_path: Path) -> None:
        self.accounts_path = Path(accounts_path)
        self._snapshot: Dict[str, Tuple[Any, ...]] = {}
        self._first = True

    def poll(self) -> Optional[AccountChange]:
        try:
            accounts = load_accounts(self.accounts_path)
        except Exception:
            # 坏文件 / 瞬态读失败:下一拍再试。save_accounts 是 tmp+replace
            # 原子写,不会读到半个文件;持续坏 = 用户的列表视图先报错。
            return None

        current = {a.uuid: _account_sig(a) for a in accounts}
        if self._first:
            # 建基线:进记录模式之前就存在的记录不算「变化」。
            self._snapshot = current
            self._first = False
            return None

        changes = [
            AccountChange(a, "new" if a.uuid not in self._snapshot else "updated")
            for a in accounts
            if a.uuid not in self._snapshot or _account_sig(a) != self._snapshot[a.uuid]
        ]
        self._snapshot = current
        if not changes:
            return None
        return max(changes, key=lambda c: c.account.last_login_time or 0)


class ProxyHandle:
    """pidfile 的薄封装:代理 PID 的读写。"""

    def __init__(self, pid_file: Path) -> None:
        self.pid_file = pid_file

    def read_pid(self) -> Optional[int]:
        try:
            return int(self.pid_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def write_pid(self, pid: int) -> None:
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.pid_file.write_text(f"{pid}\n", encoding="utf-8")

    def clear(self) -> None:
        try:
            self.pid_file.unlink()
        except OSError:
            pass


class AppModel:
    """GUI 背后的全部可变状态。**不是**线程安全的 —— Qt 主循环单线程驱动。

    注入点(测试桩替换):
        spawner(command, mitm_log_dir=...) -> (proc, log_path)
            拉起进程;proc 只需要 ``.pid`` / ``.poll()``。
        killer(pid)            停止进程
        prober(port) -> bool   端口探测
        sleep / monotonic     时钟(就绪等待不真睡)
    """

    def __init__(
        self,
        *,
        python_exe: str,
        run_mitmdump: str,
        data_dir: Optional[Path] = None,
        port: int = 443,
        spawner: Optional[Callable[..., Any]] = None,
        killer: Optional[Callable[[int], None]] = None,
        prober: Optional[Callable[[int], bool]] = None,
        sleep: Optional[Callable[[float], None]] = None,
        monotonic: Optional[Callable[[], float]] = None,
    ) -> None:
        self.python_exe = python_exe
        self.run_mitmdump = str(run_mitmdump)
        # 注入优先;默认走 paths 三级解析(env > .installed > 仓库根)。
        self.data_dir = Path(data_dir) if data_dir is not None else paths.data_dir()
        self.port = port
        self._spawner = spawner or procsup.spawn_proxy
        self._killer = killer or procsup.stop_proxy
        self._prober = prober
        self._sleep = sleep or time.sleep
        self._monotonic = monotonic or time.monotonic

        # 派生式收敛在 paths(base= 注入目录);见模块 docstring。
        self._config_path = paths.config_path(self.data_dir)
        self._accounts_path = paths.accounts_path(self.data_dir)

        self.state: str = IDLE
        self._proc: Any = None          # 本会话拉起的 Popen(收养时为 None)
        self._adopted_pid: Optional[int] = None
        self._config_fingerprint: Optional[Tuple[float, int]] = None
        self._watcher: Optional[AccountsWatcher] = None
        self._last_change: Optional[AccountChange] = None
        self._record_pending = False    # STARTING 完成后进 ADD_ACCOUNT 还是 RUNNING
        self.proxy = ProxyHandle(paths.pid_file(self.data_dir))

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    @property
    def current_pid(self) -> Optional[int]:
        """当前管理的代理 PID(本会话拉起的或收养的);None = 无。"""
        return self._proc.pid if self._proc is not None else self._adopted_pid

    def _transition(self, new_state: str) -> None:
        if new_state not in _LEGAL.get(self.state, set()):
            raise RuntimeError(f"非法状态迁移:{self.state} → {new_state}")
        self.state = new_state

    def _spawn(self, record_only: bool) -> None:
        """拉起代理进程并记 config 指纹(之后 poll() 靠它检测漂移)。"""
        command = procsup.build_proxy_command(
            self.python_exe, self.run_mitmdump, self.port, record_only=record_only
        )
        proc, _log = self._spawner(command, mitm_log_dir=paths.log_dir(self.data_dir))
        self._proc = proc
        self._adopted_pid = None
        self._record_pending = record_only
        self.proxy.write_pid(proc.pid)
        self._config_fingerprint = config_fingerprint(self._config_path)

    def _wait_ready(self, timeout: float = procsup.READY_TIMEOUT) -> str:
        """同步等就绪,三终态:ready / crashed / timeout。

        timeout(进程活着但没监听)留给 poll() 接手 —— 不是失败,见模块
        docstring 的「慢路径」。"""
        return procsup.wait_ready(
            alive=lambda: self._proc.poll() is None,
            port=self.port,
            timeout=timeout,
            sleep=self._sleep,
            monotonic=self._monotonic,
            prober=self._prober,
        )

    def _reset_session(self) -> None:
        """进程句柄 / watcher / pidfile 的一揽子清空(停止与崩溃共用)。"""
        self._proc = None
        self._adopted_pid = None
        self._watcher = None
        self._record_pending = False
        self.proxy.clear()

    def _stop_current(self) -> None:
        pid = self.current_pid
        if pid is not None:
            self._killer(pid)
        self._reset_session()

    def _enter_crashed(self) -> None:
        """进 CRASHED 前的清理:死进程句柄丢弃、pidfile 清空。

        不清 pidfile 会留两个坑:下个 GUI 会话把死 PID 当活代理「收养」;
        GUI 兜底逻辑对着死 PID 调 taskkill(无害但吵)。"""
        self._reset_session()
        self._transition(CRASHED)

    def _stop_pidfile_leftover(self) -> None:
        """IDLE 状态下残留 pidfile 指着的代理(上个 GUI 会话留下的)。

        有 pid = 我们自己的代理,直接停(状态机外操作,IDLE 没有可停的
        "当前进程");没有 = 什么都不做,端口是否被别人占由调用方的
        预检判定。"""
        pid = self.proxy.read_pid()
        if pid is not None:
            self._killer(pid)
            self.proxy.clear()

    def _finish_starting(self) -> None:
        """STARTING 的就绪收尾:按起代理时的意图进 RUNNING 或 ADD_ACCOUNT。"""
        if self._record_pending:
            self._transition(ADD_ACCOUNT)
            self._watcher = AccountsWatcher(self._accounts_path)
            # 新记录会话从零开始:上一次会话检出的变化不清掉,GUI 会在
            # 本会话第一拍立刻误弹旧账号的「设为默认?」。
            self._last_change = None
        else:
            self._transition(RUNNING)

    # ------------------------------------------------------------------
    # 公开动作(GUI 按钮背后的全部逻辑)
    # ------------------------------------------------------------------

    def adopt_or_start(self) -> str:
        """启动代理;pidfile + 端口都指向活代理则收养它。

        返回 'started' / 'adopted' / 'starting' / 'port_busy' / 'crashed'
        (状态也随之迁移;返回值只是给 GUI 提示用)。
        """
        if self.state == STARTING:
            return "starting"             # 慢启动中,重试点击不动作
        if self.state in (RUNNING, NEEDS_RESTART, ADD_ACCOUNT):
            # 代理已在本模型管理下,无需(也不允许)再来一遍。
            return "adopted" if self._proc is None else "started"

        pid = self.proxy.read_pid()
        if pid is not None and procsup.is_ready(self.port, self._prober):
            # pidfile 有记录且端口通 = 代理活着(上个 GUI 会话留下的),
            # 收养。(PID 复用误杀的残余风险已在计划里显式接受,不做映像校验。)
            self._adopted_pid = pid
            self._config_fingerprint = config_fingerprint(self._config_path)
            self._transition(RUNNING)
            log.info("收养在跑的代理:pid=%s", pid)
            return "adopted"

        if procsup.is_ready(self.port, self._prober):
            # 443 被占且没有证据是我们的(pidfile 无记录/进程已死)。
            self._transition(PORT_BUSY)
            log.error("端口 %s 被未知进程占用,拒绝启动代理", self.port)
            return "port_busy"

        self._transition(STARTING)
        self._spawn(record_only=False)
        outcome = self._wait_ready()
        if outcome == "ready":
            self._finish_starting()
            return "started"
        if outcome == "crashed":
            self._enter_crashed()
            return "crashed"
        return "starting"                 # 超时:留在 STARTING,poll() 接手

    def stop(self) -> None:
        """确保没有我们的代理在跑;本来就干净的态(IDLE / CRASHED /
        PORT_BUSY)是无操作 —— 它们没有可停的进程。"""
        if self.state in (IDLE, CRASHED, PORT_BUSY):
            return
        self._transition(STOPPING)
        self._stop_current()
        self._transition(IDLE)

    def restart(self) -> str:
        """重启(配置变更后;崩溃/端口被占后的重试也走这里)。"""
        if self.state in (RUNNING, NEEDS_RESTART, ADD_ACCOUNT):
            self._transition(STOPPING)
            self._stop_current()
            self._transition(IDLE)
        return self.adopt_or_start()

    def begin_add_account(self) -> str:
        """进入记录模式(添加账号);返回 'recording' / 'starting' /
        'port_busy' / 'crashed' / 当前状态字符串(状态不允许进入时不动作)。

        顺序是铁律:**先停现有代理,再起 record 代理** —— 记录代理必须
        在游戏登录窗出现之前就位,QR 会话中途换代理会断轮询。
        """
        if self.state == ADD_ACCOUNT:
            return "recording"
        if self.state not in (RUNNING, NEEDS_RESTART, IDLE):
            return self.state

        if self.state != IDLE:
            self._transition(STOPPING)
            self._stop_current()
            self._transition(IDLE)
        else:
            # IDLE 也可能有上个会话残留的代理占着 443,同样要先停。
            self._stop_pidfile_leftover()

        if procsup.is_ready(self.port, self._prober):
            # 停完自己人端口还被占 = 别人的进程,不碰。
            self._transition(PORT_BUSY)
            return "port_busy"

        self._transition(STARTING)
        self._spawn(record_only=True)
        outcome = self._wait_ready()
        if outcome == "ready":
            self._finish_starting()
            return "recording"
        if outcome == "crashed":
            self._enter_crashed()
            return "crashed"
        return "starting"                 # 超时:留在 STARTING,poll() 接手

    def end_add_account(self) -> None:
        """退出记录模式(停记录代理)。起正常代理是 GUI 随后调
        adopt_or_start() 的新循环 —— 中间夹着「设为默认?」对话框。"""
        if self.state != ADD_ACCOUNT:
            return
        self._transition(STOPPING)
        self._stop_current()
        self._transition(IDLE)

    def poll(self) -> None:
        """GUI 周期调用(QTimer):慢启动接手 / 代理死亡 / 配置漂移 /
        新账号落盘。"""
        if self.state == STARTING and self._proc is not None:
            if self._proc.poll() is not None:
                self._enter_crashed()
                log.error("代理进程启动中退出:pid=%s", self.current_pid)
                return
            if procsup.is_ready(self.port, self._prober):
                self._finish_starting()
                return

        if self.state in (RUNNING, ADD_ACCOUNT, NEEDS_RESTART) and self._proc is not None:
            if self._proc.poll() is not None:
                dead_pid = self.current_pid
                self._enter_crashed()
                log.error("代理进程已退出:pid=%s", dead_pid)
                return

        if self.state == RUNNING:
            fp = config_fingerprint(self._config_path)
            if fp != self._config_fingerprint:
                self._transition(NEEDS_RESTART)
                log.info("检测到配置变更,需要重启代理")

        if self.state == ADD_ACCOUNT and self._watcher is not None:
            change = self._watcher.poll()
            if change is not None:
                self._last_change = change
                log.info(
                    "添加账号:检测到记录变化(%s, uuid=%s)", change.kind, change.account.uuid
                )

    @property
    def last_account_change(self) -> Optional[AccountChange]:
        """最近一次观察到的账号变化(GUI 每拍读取;保留到被下一次变化
        覆盖 —— GUI 用状态而非消费语义,避免错过)。"""
        return self._last_change
