"""阶段 2 拦截 addon:在 mkey 反向代理上驱动 InterceptRules。

实测运行形态(开发侧取证记录,2026-10-03 取证机验证):

    hosts:  127.0.0.1 service.mkey.163.com
    mitmdump --mode reverse:https://mpay-cn.ntes53.netease.com:443 ^
      --listen-host 127.0.0.1 --listen-port 443 ^
      --set keep_host_header=true -s tools\\intercept_addon.py

SDK 自有 socket 无视系统代理,只能靠 hosts 重定向落地(reverse 上游用
CNAME 别名,避免 hosts 自环)。CA 无 pinning,直接接受本地 mitm 证书。

分工(开发侧架构拆解):

* 本文件只做「HTTPFlow ↔ InterceptRules」的搬运 + 白名单执法;
* 改写/状态机逻辑全部在 ``svs_autologin.intercept``(阶段 1,已测);
* 模拟扫码/确认是阶段 3(InterceptRules._auto_login_flow 的接线点)。

C1 零外联(docs/constraints.md):本 addon 不发起任何出站连接;
到达本监听器的流量按构造只会转发给 reverse 上游(白名单即上游本身)。
``/_idv-login/`` 前缀的请求**本地应答、绝不转发**——本地页面是工具
自己的 UI,不是 mkey 的资源。

二进制契约:QR 图片(image/png)原样转发;只有三个 JSON 端点被解析。
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

from mitmproxy import ctx, http

# 让 mitmdump 以仓库根为 cwd 启动时能 import svs_autologin
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from svs_autologin import paths  # noqa: E402
from svs_autologin.accounts import load_accounts  # noqa: E402
from svs_autologin.config import load_app_config  # noqa: E402
from svs_autologin.intercept import InterceptRules, State  # noqa: E402

# C1 例外 A:全项目唯一的生产拨号点(tools/relay_transport.py,
# tests/test_no_egress.py 的 OUTBOUND_ALLOWLIST 显式豁免)。延迟加载,
# 让本文件在无 requests 的环境下(理论上的最小部署)仍可只做被动转发。
def _make_transport():
    from relay_transport import make_transport  # noqa: E402  (tools/ 同目录)

    return make_transport()

CONFIG_PATH = paths.config_path()
ACCOUNTS_PATH = paths.accounts_path()
NOTIFY_SCRIPT = _REPO_ROOT / "tools" / "notify.ps1"

#: 记录模式(添加账号)的开关。由 run_mitmdump.py 按 mode 参数设置,
#: 本文件在 load() 里消费 —— 名字只在这一处定义。
RECORD_ONLY_ENV = "SVS_RECORD_ONLY"

#: 诊断开关:每个请求打一行完整 method + path(默认关;见 request() 注释)。
TRACE_ENV = "SVS_TRACE_HTTP"


def _effective_config(config: dict, *, record_only: bool) -> dict:
    """记录模式下的配置视图:``auto`` 表视为空,其余节原样(浅拷贝)。

    效果 = 不置 selected 标志 → 手工扫码路径(on_qrcode_query →
    on_exchange_token → _save_records)接管,扫码结果自动落盘。
    scanner[0].url 改写不受影响(阶段 2 实测:改写存在时手工扫码照常)。
    normal 模式原样返回**同一个对象**,不做无谓拷贝。
    """
    if not record_only:
        return config
    cleared = dict(config)
    cleared["auto"] = {}
    return cleared


def _notify(title: str, message: str) -> None:
    """把一条消息推到用户屏幕上(阶段 4 失败可见性)。

    自动登录跑在后台线程,失败不会体现在游戏界面上 —— 用户看到的只是
    二维码一直没人扫。msg.exe 弹窗是 Windows 自带能力,零依赖(C1/C5 之外
    不引任何东西);失败不抛 —— 通知挂了不能把登录流程也带崩。
    """
    try:
        subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy", "Bypass",
                "-File", str(NOTIFY_SCRIPT),
                "-Title", title,
                "-Message", message,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except OSError:
        ctx.log.warn(f"notify failed (title={title!r}): {message}")

# 白名单:只有这些 Host 的流量允许被解析/改写(docs/constraints.md C1)。
# 注意 reverse 模式的坑(2026-10-03 实测):``flow.request.host`` 返回的是
# **上游**主机名(mpay-cn.ntes53.netease.com),Host 头里的 service.mkey.163.com
# 要用 ``pretty_host`` 取。两个都放行——按构造 reverse 监听器上不会有别的
# Host,但规则显式写死,配置错误时宁可漏拦不可误拦。
ALLOWED_HOSTS = {"service.mkey.163.com", "mpay-cn.ntes53.netease.com"}

LOCAL_PAGE_PREFIX = "/_idv-login/"

CREATE_LOGIN_PATH = "/mpay/api/qrcode/create_login"
QRCODE_QUERY_PATH = "/mpay/api/qrcode/query"
EXCHANGE_TOKEN_PATH = "/mpay/api/users/login/qrcode/exchange_token"

# 本地占位页(阶段 4 换成真正的账号选择 UI;现在先满足
# 「登录页被替换为本地页面」的最小验收,内容零外联)。
_LOCAL_PAGE_HTML = (
    "<!doctype html><meta charset=\"utf-8\">"
    "<title>_idv-login</title>"
    "<p>svs-autologin local page (phase 2 placeholder)</p>"
)


def _json_body(content: bytes):
    """JSON body 解析;非 JSON(如 QR PNG)返回 None,调用方放行。"""
    try:
        parsed = json.loads(content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


class InterceptAddon:
    """mitmproxy addon;一个实例服务一次 mitmdump 生命周期。"""

    def __init__(self) -> None:
        self.rules: InterceptRules | None = None

    def configure(self, opts) -> None:
        """把规则层的失败接到弹窗上(阶段 4)。

        InterceptRules 刻意不知道弹窗这回事(它是纯逻辑,tests 在无 GUI 的
        环境里跑),所以「失败可见性」这一层归 addon:_run_guarded 兜住
        自动登录流程的一切异常 → 清标志、记日志,这里再加一道屏幕通知。
        """
        rules = self.rules
        if rules is None:
            return
        original = rules._run_guarded

        def guarded_and_notifying(fn):
            try:
                return original(fn)
            except Exception as exc:
                _notify("svs-autologin 自动登录失败", f"{type(exc).__name__}: {exc}")
                raise

        rules._run_guarded = guarded_and_notifying

    def load(self, loader) -> None:
        # validate=False:listen/upstream 由 mitmdump CLI 参数与 hosts 文件定义,
        # 配置文件在阶段 2 只供 auto/games 消费;完整 schema 校验留给阶段 5
        # 的安装器(那时 config.local.json 才补齐 listen/upstream 节)。
        try:
            config = load_app_config(CONFIG_PATH, validate=False)
        except Exception as exc:
            # 2026-10-23:解压出来直接双击时数据目录落在解压目录,没有
            # config.local.json;原来的裸 ConfigError 只会让代理静默崩掉。
            ctx.log.error(
                f"配置加载失败:{exc} —— 如果这是刚解压的分发包,"
                f"请先运行 tools\\setup.bat 完成安装;"
                f"如果是开发形态,把 config.example.json 复制成 config.local.json。"
            )
            raise
        # 记录模式(添加账号):auto 视为空 → 手工扫码路径落盘,不起拨号线程。
        record_only = os.environ.get(RECORD_ONLY_ENV, "") == "1"
        config = _effective_config(config, record_only=record_only)
        # 启动时读账号表 + 落盘到 accounts.json(.gitignore 已盖)。
        # auto 表非空 → 自动登录:延迟扫码线程经 transport 自己发 scan/confirm
        # (C1 例外 A,tools/relay_transport.py)。
        accounts = load_accounts(ACCOUNTS_PATH)
        auto_games = sorted(k for k, v in (config.get("auto") or {}).items() if v)
        self.rules = InterceptRules(
            config=config,
            accounts=accounts,
            state=State(),
            transport=None if record_only else (_make_transport() if auto_games else None),
            accounts_path=str(ACCOUNTS_PATH),
        )
        ctx.log.info(
            f"intercept addon ready: config={CONFIG_PATH} accounts={len(accounts)}"
            f" auto_games={auto_games} record_only={record_only}"
            f" relay={'on' if auto_games and not record_only else 'off'}"
        )
        # 预检(阶段 4):auto 指向的账号缺失/凭据不全,开工前就喊出来。
        # 记录模式 auto 为空,预检自然无话可说。
        for problem in self.rules.preflight():
            ctx.log.error(f"preflight: {problem}")
            _notify("svs-autologin 预检发现问题", problem)

        # 自检(2026-10-23):账号配置之外,hosts 与 CA 同样是自动登录成立的
        # 前提 —— 它们出问题时二维码照弹、工具却什么都看不见。在代理启动
        # 的第一秒就把话说清楚,比等用户扫一次码再猜要便宜得多。
        if not record_only and auto_games:
            for check in self._startup_checks(config, accounts, auto_games):
                if check.ok:
                    ctx.log.info(f"selfcheck {check.title}: {check.detail}")
                else:
                    ctx.log.error(f"selfcheck {check.title}: {check.detail} — {check.fix}")
                    _notify(f"svs-autologin 自检:{check.title}", f"{check.detail}\n处置:{check.fix}")

    @staticmethod
    def _startup_checks(config: dict, accounts, auto_games):
        """addon 能在监听器起来之前判断的检查项(不含 TLS 链握手)。

        TLS 链要等端口真正在听,而 mitmproxy 是在 load() 之后才 bind 的;
        那一步由拨号时的 relay_transport 自己复核(解析 + CA + 异常翻译)。
        """
        from svs_autologin import diagnostics, selfcheck
        from svs_autologin.accounts import find_by_uuid

        checks = []
        for game_id in auto_games:
            checks.append(selfcheck.check_auto_target(config, accounts, game_id))
            target = str((config.get("auto") or {}).get(game_id) or "").strip()
            checks.append(
                selfcheck.check_credential(
                    find_by_uuid(accounts, target) if target else None
                )
            )
        checks.append(selfcheck.check_hosts(diagnostics.hosts_entry()))
        checks.append(
            selfcheck.check_ca(
                paths.confdir() / "mitmproxy-ca-cert.pem",
                diagnostics.root_thumbprints(),
            )
        )
        return checks

    # ------------------------------------------------------------------
    # 请求:C1 的本地应答分支
    # ------------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        """``/_idv-login/`` 本地应答,不转发(参考实现 local_handler 契约)。"""
        # 诊断开关(默认关):mitmproxy 自带的 flow 行会截断到 50 字符,
        # 排查「exchange_token 之后那个 403 到底打的是哪个端点」时需要
        # 完整 method + path。只影响日志,不改写任何流量。
        if os.environ.get(TRACE_ENV, "") == "1":
            ctx.log.info(
                f"trace {flow.request.method} {flow.request.pretty_host}{flow.request.path}"
            )
        if flow.request.path.startswith(LOCAL_PAGE_PREFIX):
            flow.response = http.Response.make(
                200,
                _LOCAL_PAGE_HTML.encode("utf-8"),
                {"Content-Type": "text/html; charset=utf-8"},
            )
            ctx.log.info(f"local page served: {flow.request.path}")

    # ------------------------------------------------------------------
    # 响应:三个端点 → InterceptRules
    # ------------------------------------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host or flow.request.host
        if host not in ALLOWED_HOSTS:
            return  # 白名单外:原样直通,一个字节都不碰

        path = flow.request.path.split("?")[0]
        query = dict(flow.request.query)

        if path == CREATE_LOGIN_PATH:
            self._handle_create_login(flow, query)
        elif path == QRCODE_QUERY_PATH:
            self._handle_qrcode_query(flow, query)
        elif path == EXCHANGE_TOKEN_PATH:
            self._handle_exchange_token(flow, query)

    # ------------------------------------------------------------------

    def _handle_create_login(self, flow: http.HTTPFlow, query: dict) -> None:
        body = _json_body(flow.response.content or b"")
        if body is None:
            ctx.log.warn("create_login 响应不是 JSON 对象,放行不改写")
            return
        out = self.rules.on_create_login(query=query, body=body)
        # 只动 qrcode_scanners[0].url(InterceptRules 契约);重新序列化
        # 保持字段顺序,ensure_ascii=False 与服务端原始编码一致。
        flow.response.content = json.dumps(
            out, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        ctx.log.info(
            f"create_login 已拦截改写:game_id={query.get('game_id')} uuid={out.get('uuid')}"
        )

    def _handle_qrcode_query(self, flow: http.HTTPFlow, query: dict) -> None:
        body = _json_body(flow.response.content or b"")
        if body is None:
            return
        self.rules.on_qrcode_query(query=query, body=body)
        # 只观察,不改写(docs/protocol.md §6.2)

    def _handle_exchange_token(self, flow: http.HTTPFlow, query: dict) -> None:
        body = _json_body(flow.response.content or b"")
        if body is None:
            ctx.log.warn("exchange_token 响应不是 JSON 对象,跳过收尾")
            return
        self.rules.on_exchange_token(
            query=query, body=body, status=flow.response.status_code
        )
        # 自动模式不改写响应;手工模式阶段 2 也暂无字节级改写需求
        # (last_response_rewritten 只维护规则状态)。


addons = [InterceptAddon()]
