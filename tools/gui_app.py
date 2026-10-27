r"""svs-autologin GUI(阶段 5 T6)。

本文件是**唯一**的 PySide6 落点(计划红线 3):全部业务逻辑在
svs_autologin/(零 Qt、零动态执行、pytest 可测),这里只有壳 ——
窗口、按钮、定时器,把用户动作翻译成 AppModel 的方法调用。

进程契约:GUI 是 pythonw(无控制台)拉起的;代理是 GUI 用
procsup.spawn_proxy detached 拉起的独立进程,GUI 退出代理照样活
(硬需求:SDK 轮询断连不重试,代理必须常驻)。

启动按钮全流程(计划§5):同意检查(启动 GUI 时已做)→ 系统状态
检查(hosts/CA 缺失 → 「修复」= 提权重跑幂等 install.ps1)→ 起代理
(就绪探测在 AppModel)→ 起游戏(配置了 games.ma68.startup_path 且
游戏未在跑时)。

日志:GUI 进程写 <data>/log/gui.log(configure);GUI 操作事件走
logging 进 gui.log(诊断包可见);日志页双尾随 proxy.log + 最新
mitm-*.log(各自 LogTail,前缀区分)。

用法(dev 与安装版同形)::

    pythonw.exe tools\gui_app.py          # 常规启动(同意检查在 C6 对话框)
    python.exe tools\gui_app.py           # 调试(有控制台,日志也进 stderr)
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# tools/ 也必须在 sys.path 上:GUI 的 TLS 链自检要 import relay_transport。
# embed 解释器的 python312._pth 是隔离模式,运行脚本时不会自动把脚本目录
# 放进 sys.path(2026-10-23 现场:自检报 ModuleNotFoundError: relay_transport)。
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from svs_autologin import __version__, consent, diagnostics, paths, selfcheck  # noqa: E402
from svs_autologin.accounts import delete_account, load_accounts, save_accounts  # noqa: E402
from svs_autologin.appmodel import ADD_ACCOUNT, AppModel  # noqa: E402
from svs_autologin.config import load_app_config  # noqa: E402
from svs_autologin.config_editor import edit_auto, set_startup_path  # noqa: E402
from svs_autologin.logging_setup import configure as configure_logging  # noqa: E402
from svs_autologin.logtail import LogTail, current_mitm_log  # noqa: E402
from svs_autologin import procsup  # noqa: E402

from PySide6.QtCore import Qt, QTimer, QLockFile
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

#: 主状态轮询间隔(秒):慢启动接手 / 死亡检测 / 配置漂移 / 账号变化。
POLL_INTERVAL_MS = 1000

#: 日志页缓冲行数上限(超出截头;诊断包里才有完整文件,页面只管「现场」)。
LOG_BUFFER_LINES = 2000

#: 唯一游戏短 ID(全部配置键的公共后缀:auto.<GAME_ID> /
#: games.<GAME_ID>.startup_path)。提为常量:字符串散在 handler 里是
#: Primitive Obsession,改游戏时没有单一改动点。
GAME_ID = "ma68"

#: 同意书全文(C6:四条,拒绝 = 退出)。
CONSENT_TEXT = """<b>使用本工具前,请阅读并确认以下事项:</b><ol>
<li>本工具会在本机解密并改写游戏登录相关的网络流量(HTTP/TLS 拦截)。</li>
<li>使用第三方工具登录游戏存在账号风险,由此产生的封号等后果由使用者自行承担。</li>
<li>扫码授权后,登录凭据(token)会以明文形式保存在本机数据目录中。</li>
<li>本工具已移除参考实现中的远程代码执行(RCE)缺陷,但源码公开可查。</li>
</ol>"""

STATE_LABELS = {
    "idle": "未运行",
    "starting": "启动中…",
    "running": "运行中",
    "needs_restart": "配置已变更,需重启代理",
    "add_account": "记录模式(等待扫码)",
    "stopping": "停止中…",
    "port_busy": "端口 443 被占用",
    "crashed": "代理已崩溃",
}

gui_log = logging.getLogger("svs.gui")


class ConsentDialog(QDialog):
    """首跑知情同意(C6)。拒绝 = 关闭 GUI;同意只弹一次。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"svs-autologin {__version__} - 使用须知")
        self.setModal(True)
        layout = QVBoxLayout(self)
        label = QLabel(CONSENT_TEXT)
        label.setTextFormat(Qt.RichText)
        layout.addWidget(label)
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.button(QDialogButtonBox.Ok).setText("我已阅读并同意")
        buttons.button(QDialogButtonBox.Cancel).setText("退出")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class MainWindow(QMainWindow):
    def __init__(self, app_model: AppModel) -> None:
        super().__init__()
        self.model = app_model
        self.setWindowTitle(f"svs-autologin {__version__}")
        self.resize(760, 520)
        self._handling_change = False   # 「设为默认?」弹窗期间的重入门闩
        self._start_hint_shown = False  # 「请现在打开游戏」只弹一次

        # ---- 日志尾随 ----
        log_dir = paths.log_dir()
        self._proxy_tail = LogTail(log_dir / "proxy.log")
        self._mitm_tail: LogTail | None = None
        self._mitm_path: Path | None = None

        # ---- 顶层结构:状态栏 + 选项卡 ----
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        self.status_label = QLabel("…")
        root_layout.addWidget(self.status_label)
        # 自动登录就绪状态:账号记录成功 ≠ 自动登录会触发。这一行专门回答
        # 「现在点启动,游戏会不会自己登进去」,是 2026-10-23 那次「账号有了、
        # 登录不动」的直接可见化。
        self.auto_label = QLabel("自动登录:…")
        root_layout.addWidget(self.auto_label)

        tabs = QTabWidget()
        root_layout.addWidget(tabs, stretch=1)
        tabs.addTab(self._build_main_tab(), "主界面")
        tabs.addTab(self._build_settings_tab(), "设置")
        tabs.addTab(self._build_log_tab(), "日志")

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_poll)
        self._timer.start(POLL_INTERVAL_MS)
        self._refresh_autologin_status()

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _build_main_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 账号列表
        layout.addWidget(QLabel("账号(选中即设为默认账号):"))
        self.account_list = QListWidget()
        self.account_list.currentItemChanged.connect(self._on_account_selected)
        layout.addWidget(self.account_list, stretch=1)

        # 账号操作行
        row1 = QHBoxLayout()
        self.rename_btn = QPushButton("重命名")
        self.rename_btn.clicked.connect(self._on_rename)
        self.delete_btn = QPushButton("删除")
        self.delete_btn.clicked.connect(self._on_delete)
        self.add_btn = QPushButton("添加账号(扫码)")
        self.add_btn.clicked.connect(self._on_add_account)
        row1.addWidget(self.rename_btn)
        row1.addWidget(self.delete_btn)
        row1.addWidget(self.add_btn)
        row1.addStretch(1)
        layout.addLayout(row1)

        # 代理控制行
        row2 = QHBoxLayout()
        self.start_btn = QPushButton("启动")
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self._on_stop)
        self.restart_btn = QPushButton("重启代理")
        self.restart_btn.clicked.connect(self._on_restart)
        self.export_btn = QPushButton("导出诊断包")
        self.export_btn.clicked.connect(self._on_export)
        self.selfcheck_btn = QPushButton("自检")
        self.selfcheck_btn.clicked.connect(self._on_selfcheck)
        row2.addWidget(self.start_btn)
        row2.addWidget(self.stop_btn)
        row2.addWidget(self.restart_btn)
        row2.addWidget(self.selfcheck_btn)
        row2.addWidget(self.export_btn)
        row2.addStretch(1)
        layout.addLayout(row2)

        return tab

    def _build_settings_tab(self) -> QWidget:
        """设置页:目前只有游戏路径(games.<GAME_ID>.startup_path)。"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel(
            "游戏程序(exe)路径 —— 配置后「启动」会在代理就绪后自动开游戏;"
            "留空 = 只起代理,不开游戏。"
        ))
        row = QHBoxLayout()
        self.game_path_edit = QPlainTextEdit()
        self.game_path_edit.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.game_path_edit.setFixedHeight(28)
        self.game_path_edit.setPlaceholderText(r"例:D:\Games\Shadowverse\game.exe")
        row.addWidget(self.game_path_edit, stretch=1)
        self.browse_btn = QPushButton("浏览…")
        self.browse_btn.clicked.connect(self._on_browse_game)
        row.addWidget(self.browse_btn)
        self.save_path_btn = QPushButton("保存")
        self.save_path_btn.clicked.connect(self._on_save_game_path)
        row.addWidget(self.save_path_btn)
        layout.addLayout(row)
        layout.addStretch(1)
        self._reload_game_path()
        return tab

    def _build_log_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(LOG_BUFFER_LINES)
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self.log_view)
        return tab

    # ------------------------------------------------------------------
    # 设置页
    # ------------------------------------------------------------------

    def _reload_game_path(self) -> None:
        try:
            config = load_app_config(paths.config_path(), validate=False)
            game = (config.get("games") or {}).get(GAME_ID) or {}
            self.game_path_edit.setPlainText(str(game.get("startup_path") or ""))
        except Exception:
            self.game_path_edit.setPlainText("")

    def _on_browse_game(self) -> None:
        exe, _ = QFileDialog.getOpenFileName(
            self, "选择游戏程序", "", "可执行文件 (*.exe)"
        )
        if exe:
            self.game_path_edit.setPlainText(exe)

    def _on_save_game_path(self) -> None:
        exe = self.game_path_edit.toPlainText().strip()
        try:
            set_startup_path(paths.config_path(), GAME_ID, exe or None)
        except Exception as exc:
            QMessageBox.warning(self, "保存失败", str(exc))
            return
        self._event(f"游戏路径已保存:{exe or '(清除)'}")
        QMessageBox.information(self, "设置", "已保存。")

    # ------------------------------------------------------------------
    # 账号列表
    # ------------------------------------------------------------------

    def refresh_accounts(self) -> None:
        """重读账号表 + auto 指向,重建列表(选中行 = 当前默认账号)。"""
        accounts = load_accounts(paths.accounts_path())
        try:
            config = load_app_config(paths.config_path(), validate=False)
            auto_uuid = (config.get("auto") or {}).get(GAME_ID, "")
        except Exception:
            auto_uuid = ""
        self.account_list.clear()
        for account in accounts:
            marker = " [默认]" if account.uuid == auto_uuid else ""
            item = QListWidgetItem(f"{account.name}  ({account.uuid}){marker}")
            item.setData(Qt.UserRole, account.uuid)
            self.account_list.addItem(item)
        # 空列表提示
        if not accounts:
            self.account_list.addItem(QListWidgetItem("(无账号 — 点击「添加账号」扫码录入)"))
        self._refresh_autologin_status()

    def _on_account_selected(self, current, _previous) -> None:
        if current is None:
            return
        uuid = current.data(Qt.UserRole)
        if not uuid:
            return  # 占位行
        try:
            edit_auto(paths.config_path(), GAME_ID, uuid)
            self._event(f"默认账号已设为 {uuid}")
            self._refresh_autologin_status()
        except Exception as exc:
            QMessageBox.warning(self, "设置默认账号失败", str(exc))

    def _on_rename(self) -> None:
        item = self.account_list.currentItem()
        if item is None or not item.data(Qt.UserRole):
            QMessageBox.information(self, "重命名", "请先选择一个账号。")
            return
        uuid = item.data(Qt.UserRole)
        accounts = load_accounts(paths.accounts_path())
        account = next((a for a in accounts if a.uuid == uuid), None)
        if account is None:
            return
        name, ok = QInputDialog.getText(
            self, "重命名", "新名字(留空回落 uuid):", text=account.name
        )
        if not ok:
            return
        account.name = name or account.uuid
        save_accounts(accounts, paths.accounts_path())
        self.refresh_accounts()

    def _on_delete(self) -> None:
        item = self.account_list.currentItem()
        if item is None or not item.data(Qt.UserRole):
            QMessageBox.information(self, "删除账号", "请先选择一个账号。")
            return
        uuid = item.data(Qt.UserRole)
        if QMessageBox.question(
            self, "删除账号", f"确定删除 {uuid}?\n(其登录凭据将从本机移除)"
        ) != QMessageBox.Yes:
            return
        accounts = load_accounts(paths.accounts_path())
        try:
            cleared = delete_account(accounts, uuid, config=self._load_config_for_delete())
            save_accounts(accounts, paths.accounts_path())
            self._write_config_after_delete(cleared)
        except Exception as exc:
            QMessageBox.warning(self, "删除失败", str(exc))
            return
        self._event(f"账号已删除:{uuid}")
        self.refresh_accounts()

    def _load_config_for_delete(self):
        try:
            return load_app_config(paths.config_path(), validate=False)
        except Exception:
            return None

    def _write_config_after_delete(self, cleared) -> None:
        """delete_account 改的是内存 config;auto 清理落盘走 config_editor。"""
        if not cleared:
            return
        for game_id in cleared:
            try:
                edit_auto(paths.config_path(), game_id, "")
            except Exception:
                pass  # auto 清理失败不阻断删除流程

    # ------------------------------------------------------------------
    # 自检(2026-10-23):账号 / hosts / CA / 代理 / TLS 链路
    # ------------------------------------------------------------------

    def _ca_file(self) -> Path:
        return paths.confdir() / "mitmproxy-ca-cert.pem"

    def _refresh_autologin_status(self) -> None:
        """状态栏第二行:自动登录现在会不会触发。

        只读本地配置与账号文件,不探测网络 —— 会被 __init__ 和每次账号
        操作调用,不能有副作用。
        """
        try:
            config = load_app_config(paths.config_path(), validate=False)
        except Exception:
            self.auto_label.setText("自动登录:配置文件读不出来(点「自检」)")
            return
        try:
            accounts = load_accounts(paths.accounts_path())
        except Exception:
            accounts = []
        self.auto_label.setText(
            "自动登录:" + selfcheck.auto_summary(config, accounts, GAME_ID)
        )

    def _collect_checks(self):
        """跑全部自检项;单个探针失败只降级成一条结果,不把 GUI 带崩。"""
        try:
            config = load_app_config(paths.config_path(), validate=False)
            config_error = None
        except Exception as exc:
            config, config_error = {}, exc
        try:
            accounts = load_accounts(paths.accounts_path())
        except Exception:
            accounts = []

        try:
            hosts_line = diagnostics.hosts_entry()
        except Exception:
            hosts_line = None
        try:
            thumbs = diagnostics.root_thumbprints()
        except Exception:
            thumbs = []
        try:
            listening = procsup.is_ready(self.model.port)
        except Exception:
            listening = False

        chain = None
        if listening:
            try:
                from relay_transport import probe_chain

                chain = tuple(probe_chain())
            except Exception as exc:
                chain = (False, f"TLS 探针异常:{type(exc).__name__}: {exc}")

        return selfcheck.run_checks(
            config=config,
            accounts=accounts,
            game_id=GAME_ID,
            ca_file=self._ca_file(),
            hosts_line=hosts_line,
            root_thumbprints=thumbs,
            listening=listening,
            chain=chain,
            config_error=config_error,
            port=self.model.port,
        )

    def _run_selfcheck(self, *, show_dialog: bool):
        try:
            checks = self._collect_checks()
        except Exception as exc:  # 自检自己不能成为新的故障源
            gui_log.exception("自检失败")
            if show_dialog:
                QMessageBox.critical(self, "自检失败", f"{type(exc).__name__}: {exc}")
            return []
        for check in checks:
            if not check.ok:
                gui_log.info("自检未通过 [%s]:%s", check.key, check.detail)
        self._refresh_autologin_status()
        if show_dialog:
            QMessageBox.information(
                self, "自动登录自检", selfcheck.format_report(checks)
            )
        return checks

    def _system_problems(self):
        """启动前必须成立的两项:hosts 指向回环 + 本目录 CA 受信任。"""
        problems = []
        try:
            line = diagnostics.hosts_entry()
        except Exception:
            line = None
        hosts = selfcheck.check_hosts(line)
        if not hosts.ok:
            problems.append(hosts)
        try:
            thumbs = diagnostics.root_thumbprints()
        except Exception:
            thumbs = []
        ca = selfcheck.check_ca(self._ca_file(), thumbs)
        if not ca.ok:
            problems.append(ca)
        return problems

    def _repair_system(self) -> bool:
        """重跑幂等安装器(hosts + CA 导入);需要管理员权限。"""
        self._event("修复系统状态:重跑 install.ps1")
        import subprocess

        installer = _REPO_ROOT / "tools" / "install.ps1"
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(installer)],
                capture_output=True, timeout=300, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            QMessageBox.critical(self, "修复失败", f"无法运行安装器:{exc}")
            return False
        if proc.returncode != 0:
            output = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()
            QMessageBox.critical(
                self,
                "修复失败",
                f"安装器退出码 {proc.returncode}。\n{output[-800:]}\n\n"
                "如果提示拒绝访问:安装器需要管理员权限 —— "
                "请右键 tools\\setup.bat「以管理员身份运行」,再从主界面点「启动」。",
            )
            return False
        QMessageBox.information(self, "修复完成", "系统状态已修复。")
        return True

    def _system_check(self) -> bool:
        """启动前置检查:hosts 条目 + CA 指纹在信任库(计划§5)。

        缺 → 问「修复?」→ 提权重跑幂等 install.ps1(唯一系统变更点)。
        返回 True = 检查通过(或修复并复查通过),可以继续起代理。
        """
        problems = self._system_problems()
        if not problems:
            return True
        text = "检测到问题:\n- " + "\n- ".join(
            f"{p.title}:{p.detail}" for p in problems
        ) + "\n\n现在修复?(需要管理员权限,会重跑安装器)"
        if QMessageBox.question(self, "系统状态检查", text) != QMessageBox.Yes:
            return False
        if not self._repair_system():
            return False
        remaining = self._system_problems()
        if remaining:
            QMessageBox.warning(
                self,
                "仍有问题",
                "\n".join(f"{p.title}:{p.detail}" for p in remaining),
            )
            return False
        return True

    def _on_selfcheck(self) -> None:
        checks = self._run_selfcheck(show_dialog=True)
        blocking = [
            c for c in selfcheck.fatal_problems(checks) if c.key in ("hosts", "ca")
        ]
        if blocking and QMessageBox.question(
            self,
            "修复系统状态",
            "hosts / 证书问题可以用安装器修复(需要管理员权限)。现在修复?",
        ) == QMessageBox.Yes:
            if self._repair_system():
                self._run_selfcheck(show_dialog=True)

    # ------------------------------------------------------------------
    # 代理控制
    # ------------------------------------------------------------------

    def _game_startup_path(self) -> str:
        try:
            config = load_app_config(paths.config_path(), validate=False)
            game = (config.get("games") or {}).get(GAME_ID) or {}
            return str(game.get("startup_path") or "")
        except Exception:
            return ""

    def _on_start(self) -> None:
        """启动全流程:系统检查(可修复)→ 起代理 → 自检 → 起游戏。

        自检不过就不拉游戏:那种情况下游戏起来只会看到一个永远不动的二维码,
        比明确的报错更难理解。代理仍然留在运行状态,修好后再点启动即可。
        """
        if not self._system_check():
            return
        # 配置/账号/CA 的问题不等到代理起来才发现:缺 config.local.json 时
        # 代理进程会直接崩(2026-10-23 现场),这里先拦下并说清楚。
        pre = self._run_selfcheck(show_dialog=False)
        blocking = [
            c for c in selfcheck.fatal_problems(pre)
            if c.key in ("config", "auto_target", "credential", "hosts", "ca")
        ]
        if blocking:
            # 只有「凭据过期」时给一条直接出路:进记录模式重新扫码。
            if all(c.key == "credential" for c in blocking):
                expired = blocking[0]
                if QMessageBox.question(
                    self,
                    "账号凭据已过期",
                    f"{expired.detail}\n\n现在进入「添加账号」重新扫码一次?",
                ) == QMessageBox.Yes:
                    self._on_add_account()
                return
            QMessageBox.warning(
                self,
                "自动登录的条件还不满足",
                "先修好再启动:\n\n"
                + "\n".join(f"· {c.title}:{c.detail}" for c in blocking)
                + "\n\n点「自检」可以看到每一项的处置。",
            )
            return
        outcome = self.model.adopt_or_start()
        self._report_outcome(outcome)
        self._refresh_autologin_status()
        if outcome not in ("started", "adopted"):
            return

        checks = self._run_selfcheck(show_dialog=False)
        fatal = selfcheck.fatal_problems(checks)
        if fatal:
            QMessageBox.warning(
                self,
                "自动登录自检未通过",
                "代理已启动,但现在自动登录不会成功:\n\n"
                + "\n".join(f"· {c.title}:{c.detail}" for c in fatal)
                + "\n\n点「自检」查看处置;修好后重新点「启动」。",
            )
            return

        exe = self._game_startup_path()
        if not exe:
            if not self._start_hint_shown:
                self._start_hint_shown = True
                QMessageBox.information(
                    self,
                    "打开游戏",
                    "代理已就绪,自动登录已启用。\n\n"
                    "请现在打开游戏 —— 必须在代理启动之后打开;\n"
                    "游戏先开着再点启动,这一次登录窗口不会被接管。\n\n"
                    "想让它自动开游戏,可以在「设置」里填游戏 exe 路径。",
                )
            else:
                self._event("代理已就绪;请在此时打开游戏")
            return
        # 已知怪癖:旧实例活着时新启动静默无进程 —— 已在跑就跳过。
        running = procsup.find_game_processes(str(Path(exe).parent))
        if running:
            QMessageBox.information(
                self,
                "游戏已在运行",
                f"检测到游戏已在运行(pid={running[0]}),没有重复启动。\n\n"
                "自动登录只接管代理启动后新开的登录窗口;\n"
                "如果游戏是代理启动前开的,请关掉游戏再重新打开。",
            )
            return
        if procsup.launch_game(exe) is None:
            QMessageBox.warning(
                self, "启动游戏失败",
                f"代理已启动,但游戏无法拉起:\n{exe}\n(可在「设置」里检查路径)",
            )

    def _on_stop(self) -> None:
        self.model.stop()
        self._report_outcome("stopped")

    def _on_restart(self) -> None:
        outcome = self.model.restart()
        self._report_outcome(outcome)
        self._refresh_autologin_status()
        if outcome in ("started", "adopted"):
            self._run_selfcheck(show_dialog=False)

    def _report_outcome(self, outcome: str) -> None:
        hint = {
            "started": "代理已启动。",
            "adopted": "已接管上一会话的代理。",
            "starting": "代理启动中(冷启动较慢,最长 30 秒)…",
            "recording": "记录模式已开启 — 请在游戏登录窗用手机扫码。",
            "port_busy": "端口 443 被其他程序占用,代理无法启动。",
            "crashed": "代理进程启动失败(已崩溃),详见日志页。",
            "stopped": "代理已停止。",
        }.get(outcome)
        if hint:
            self._append_log(f"[gui] {hint}")
            gui_log.info(hint)
        if outcome in ("port_busy", "crashed"):
            QMessageBox.warning(self, "svs-autologin", hint or outcome)

    # ------------------------------------------------------------------
    # 添加账号
    # ------------------------------------------------------------------

    def _close_game_for_record(self) -> bool:
        """记录模式铁律:记录代理必须在游戏登录窗**之前**就位 —— 游戏在跑
        就先关掉(登录窗的 QR 会话中途换代理会断轮询)。失败 = 放弃进入。"""
        exe = self._game_startup_path()
        if not exe:
            return True  # 没配路径:无法自动关,靠用户自己重开登录窗
        pids = procsup.find_game_processes(str(Path(exe).parent))
        if not pids:
            return True
        if QMessageBox.question(
            self, "关闭游戏",
            "添加账号前需要先关闭游戏(记录代理必须先于登录窗就位)。\n"
            "现在关闭?",
        ) != QMessageBox.Yes:
            return False
        for pid in pids:
            procsup.stop_proxy(pid)
        self._event(f"游戏已关闭(pid={','.join(map(str, pids))})")
        return True

    def _on_add_account(self) -> None:
        """先关游戏(在跑时)→ 停正常代理 → 起 record 代理 → 提示扫码。"""
        answer = QMessageBox.question(
            self,
            "添加账号",
            "即将进入记录模式:\n"
            "1. 游戏在运行会先被关闭;\n"
            "2. 当前代理会先停止;\n"
            "3. 记录代理就位后,请打开游戏登录窗用手机扫码;\n"
            "4. 二维码约 3 分钟过期;登录窗需要重新打开。\n\n"
            "继续?",
        )
        if answer != QMessageBox.Yes:
            return
        if not self._close_game_for_record():
            return
        outcome = self.model.begin_add_account()
        if outcome != "recording":
            self._report_outcome(outcome)
            return
        self._report_outcome("recording")
        QMessageBox.information(
            self,
            "记录模式",
            "记录模式已开启。\n请打开游戏登录窗并用手机扫码。\n"
            "检测到登录成功后,会询问是否设为默认账号。",
        )

    def _on_poll_add_account(self) -> None:
        """ADD_ACCOUNT 期间:检测到变化 → 弹「设为默认?」→ 回正常代理。

        只在 state == ADD_ACCOUNT 且有未处理的检出口响:离开 ADD_ACCOUNT
        后 last_account_change 仍保留(日志/诊断可查),但不响应。
        QMessageBox 打开期间 QTimer 照跑(嵌套事件循环),靠 _handling_change
        门闩防止每秒叠一层对话框。"""
        if self._handling_change:
            return
        if self.model.state != ADD_ACCOUNT:
            return
        change = self.model.last_account_change
        if change is None:
            return
        self._handling_change = True
        try:
            account = change.account
            set_default = QMessageBox.question(
                self,
                "检测到账号",
                f"检测到扫码登录:{account.name}({account.uuid})\n\n设为默认账号?",
            )
            if set_default == QMessageBox.Yes:
                try:
                    edit_auto(paths.config_path(), GAME_ID, account.uuid)
                    gui_log.info("新账号已设为默认:%s", account.uuid)
                except Exception as exc:
                    QMessageBox.warning(self, "设默认失败", str(exc))
        finally:
            self._handling_change = False
        self.model.end_add_account()
        outcome = self.model.adopt_or_start()
        self._report_outcome(outcome)
        self.refresh_accounts()

    # ------------------------------------------------------------------
    # 诊断导出
    # ------------------------------------------------------------------

    def _on_export(self) -> None:
        try:
            zip_path = diagnostics.collect_bundle(paths.data_dir())
        except Exception as exc:
            QMessageBox.critical(self, "导出诊断包", f"导出失败:{exc}")
            return
        self._event(f"诊断包已导出:{zip_path}")
        if QMessageBox.question(
            self, "导出诊断包", f"诊断包已生成:\n{zip_path}\n\n打开所在文件夹?"
        ) == QMessageBox.Yes:
            os.startfile(str(zip_path.parent))  # noqa: PTH - Windows only

    # ------------------------------------------------------------------
    # 轮询
    # ------------------------------------------------------------------

    def _on_poll(self) -> None:
        self.model.poll()
        self._on_poll_add_account()
        self.status_label.setText(f"状态:{STATE_LABELS.get(self.model.state, self.model.state)}")
        self._tail_logs()

    # ------------------------------------------------------------------
    # 日志尾随 + 事件
    # ------------------------------------------------------------------

    def _event(self, text: str) -> None:
        """GUI 操作事件:进 gui.log(→ 诊断包)+ 日志页,双落点一致。"""
        gui_log.info("%s", text)
        self._append_log(f"[gui] {text}")

    def _append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    def _tail_logs(self) -> None:
        """proxy.log + 最新 mitm-*.log 的增量行 → 日志页(带前缀)。"""
        for line in self._proxy_tail.poll():
            self._append_log(f"[proxy] {line}")
        # mitm 日志可能换文件(代理重启):路径变了就换尾随器
        latest = current_mitm_log(paths.log_dir())
        if latest is not None and latest != self._mitm_path:
            self._mitm_path = latest
            self._mitm_tail = LogTail(latest)
        if self._mitm_tail is not None:
            for line in self._mitm_tail.poll():
                self._append_log(f"[mitm] {line}")


def _native_message(text: str, title: str = "svs-autologin") -> None:
    """没有 Qt 时的最后一条消息通道。

    pythonw 没有控制台,未捕获异常 + 日志不可写 = 双击后什么都不发生
    (2026-10-23 的现场:进程被系统降权到 Low IL,连 gui.log 都打不开)。
    MessageBoxW 走 user32,不依赖 Qt、不依赖日志。
    """
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)  # MB_ICONERROR
    except Exception:
        pass


def _excepthook(exc_type, exc, tb) -> None:
    """未捕获异常:写 gui.log;pythonw 下必须弹出来,否则等于静默退出。"""
    text = "".join(traceback.format_exception(exc_type, exc, tb))
    logging.getLogger(__name__).error("未捕获异常:\n%s", text)
    message = f"发生未处理的错误:\n{exc}\n\n详见 gui.log"
    try:
        if QApplication.instance() is not None:
            QMessageBox.critical(None, "svs-autologin", message)
            return
    except Exception:
        pass
    _native_message(message + "\n\n(完整堆栈见日志文件)")


def _configure_logging_with_fallback(primary: Path) -> Path:
    """打开 GUI 日志;数据目录不可写时退到程序目录并明确告知。

    日志是 ``main()`` 的**第一步**,它失败就意味着:没有窗口、没有日志、
    没有事件日志 —— 用户看到的只有「点不开」。所以这里两层兜底:

    1. 程序目录下的 ``log\\gui.log``(安装形态下通常与程序同权,可写);
    2. 两条路都不通才弹 MessageBox,然后让异常照常冒泡(用户至少看到原因)。
    """
    try:
        configure_logging(log_file=str(primary))
        return primary
    except Exception as exc:
        fallback = _REPO_ROOT / "log" / "gui.log"
        try:
            configure_logging(log_file=str(fallback))
        except Exception:
            _native_message(
                "无法写日志文件:\n"
                f"{primary}\n\n{type(exc).__name__}: {exc}\n\n"
                f"备用路径也不可写:{fallback}\n\n"
                "程序或数据目录没有写权限。若程序放在受限目录/沙箱工作区里,"
                "请换到普通用户可写的位置,或用管理员身份重新安装。",
            )
            raise
        _native_message(
            "警告:无法写入常规日志路径\n"
            f"{primary}\n\n{type(exc).__name__}: {exc}\n\n"
            f"已改用:{fallback}\n\n"
            "这通常意味着程序目录所在的位置会限制进程权限(例如被降权运行的"
            "工作区)。窗口仍会打开,但账号/配置的保存可能失败。",
        )
        return fallback


def _run_installer_elevated() -> bool:
    """以管理员身份跑 install.ps1,返回「安装标记出现了吗」。

    2026-10-23 现场:用户把 zip 解压出来直接双击 exe,没有安装标记 →
    数据目录落在解压目录、没有 config.local.json → 代理一启动就崩,只剩
    「代理进程启动失败」五个字。这里把「先装再用」变成 GUI 里点一下的事。

    用 install.ps1 而不是 setup.bat:后者末尾有 ``pause``,``-Wait`` 会一直
    等到用户在提权窗口里按键。提权窗口跑完 install.ps1 会自己关掉。
    提权进程的退出码拿不到,所以以**安装标记**为成功判据(它由安装器在
    最后一步原子写入)。
    """
    import subprocess

    installer = _REPO_ROOT / "tools" / "install.ps1"
    if not installer.exists():
        QMessageBox.critical(None, "svs-autologin", f"安装脚本缺失:{installer}")
        return False
    argument_list = (
        f'-NoProfile -ExecutionPolicy Bypass -File "{installer}"'
    )
    # 外层用单引号包参数列表:路径里的单引号(用户名 O'Brien 一类)按
    # PowerShell 规则双写转义,避免命令行被切断。
    safe_argument_list = argument_list.replace("'", "''")
    try:
        subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Start-Process -FilePath 'powershell' -Verb RunAs -Wait "
                f"-ArgumentList '{safe_argument_list}'",
            ],
            capture_output=True,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        gui_log.error("提权安装失败:%r", exc)
        return False
    return (_REPO_ROOT / paths.INSTALLED_MARKER).exists()


def _offer_install() -> bool:
    """未安装的分发包:解释清楚 + 一键安装。返回 True = 装好了。"""
    answer = QMessageBox.question(
        None,
        "svs-autologin 尚未安装",
        "这个程序目录还没有安装。\n\n"
        "安装会做三件事(需要管理员权限,会弹 UAC):\n"
        "  1. 生成本机专用的解密证书并加入系统信任区;\n"
        "  2. 在 hosts 里加一条指向本机的登录域名;\n"
        "  3. 建立数据目录(C:\\ProgramData\\svs-autologin)与开始菜单快捷方式。\n\n"
        "如果不想现在安装,可以关闭本窗口,右键 tools\\setup.bat "
        "「以管理员身份运行」。\n\n现在安装吗?",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.Yes,
    )
    if answer != QMessageBox.Yes:
        return False
    gui_log.info("用户请求安装:%s", _REPO_ROOT)
    if _run_installer_elevated():
        return True
    QMessageBox.critical(
        None,
        "安装未完成",
        "没有检测到安装标记,安装可能被取消(UAC)或中途失败。\n\n"
        "可以稍后右键 tools\\setup.bat「以管理员身份运行」重试;"
        "详细输出在那个提权窗口里。",
    )
    return False


def _relaunch() -> None:
    """装好后重开自己:数据目录已切到 ProgramData,旧进程还按解压目录算。"""
    import subprocess

    try:
        subprocess.Popen(
            [sys.executable, str(_REPO_ROOT / "tools" / "gui_app.py")],
            cwd=str(_REPO_ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,   # CREATE_NO_WINDOW
        )
    except OSError as exc:
        gui_log.error("重启 GUI 失败:%r", exc)


def main() -> int:
    # 先装异常钩子:pythonw 没有控制台,任何未捕获异常都必须变成可见的弹窗。
    sys.excepthook = _excepthook

    data_dir = paths.data_dir()

    # 日志是第一步,必须能失败得有交代(2026-10-23:这里抛 PermissionError
    # → 双击后无窗口、无日志,用户只能看到「点不开」)。
    log_path = _configure_logging_with_fallback(data_dir / "log" / "gui.log")
    gui_log.info("启动:data_dir=%s log=%s", data_dir, log_path)

    # 单实例:双开 GUI = 两套状态机对着同一个 pidfile/端口打架。
    # stale 10s —— 上一个实例硬崩后锁文件残留,10 秒后允许接管。
    lock = QLockFile(str(data_dir / "gui.lock"))
    lock.setStaleLockTime(10_000)
    if not lock.tryLock(0):  # PySide6 的 tryLock 必须给超时;0 = 立即返回不等待
        QMessageBox.critical(
            None, "svs-autologin", "另一个 svs-autologin 窗口已在运行。"
        )
        return 1

    app = QApplication(sys.argv)
    app.setApplicationName("svs-autologin")

    # 分发版但没安装:先说清楚,别让它以开发回退形态跑出一个崩溃的代理。
    if paths.is_uninstalled_distribution():
        installed = _offer_install()
        lock.unlock()
        if not installed:
            return 1
        QMessageBox.information(
            None, "安装完成", "安装完成。程序会重新打开(正在启动)。"
        )
        _relaunch()
        return 0

    # C6:首跑同意(拒绝 = 退出;同意落 consent.json,只弹一次)。
    if not consent.has_consented(data_dir):
        if ConsentDialog().exec() != QDialog.Accepted:
            return 1
        consent.mark_consented(data_dir, __version__)

    model = AppModel(
        python_exe=sys.executable,
        run_mitmdump=str(_REPO_ROOT / "tools" / "run_mitmdump.py"),
    )
    win = MainWindow(model)
    win.refresh_accounts()
    win.show()
    # 启动后跑一次静默自检:失败只写日志页/gui.log,不打断用户。
    # 300ms 让窗口先画出来,避免对话框盖在未绘制的窗口上。
    QTimer.singleShot(300, lambda: win._run_selfcheck(show_dialog=False))
    rc = app.exec()
    lock.unlock()
    return rc


if __name__ == "__main__":
    sys.exit(main())
