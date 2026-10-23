r"""唯一的生产拨号点(docs/constraints.md C1 例外 A,2026-10-12 拍板)。

自动登录要顶替手机的位置,自己发两个请求(``qrcode/scan`` 与
``qrcode/confirm_login`` —— 协议见 开发侧取证记录「阶段 3 协议」)。
游戏的换票请求体里没有 uuid,凭据只能在 confirm 那一步由扫码方喂进去,
所以这两个包**必须**由工具发起 —— 这是 C1「工具自己不发请求」唯一的例外。

约束(与 C1 例外条款一致):

* 本文件是全项目**唯一**允许出现出站客户端调用的源文件;
  ``tests/test_no_egress.py`` 的 ``OUTBOUND_ALLOWLIST`` 显式豁免且仅豁免它。
* 只连 ``https://service.mkey.163.com``(mkey 自己的端点,白名单成员);
  base_url 来自 config 的 ``qrcode`` 节,**必须**是 https://。
* 出站走 hosts 重定向进入本地 443 反代,再由反代转发给真实 mkey ——
  与游戏的流量同一条路、同一套审计日志,不另开直连通道。
* TLS 用本地 mitm CA 校验(``verify`` 指到 mitmproxy-ca-cert.pem 或 false);
  mkey 无 pinning(阶段 2 实测)。

接口对齐 ``svs_autologin.qrcode_login.Transport``:

    (method, url, *, params, data, headers, verify, timeout) -> (status, json|None)

``json`` 在响应体不是 JSON 对象时为 None。同步、线程安全(requests.Session
按请求使用;自动登录流程跑在延迟扫码线程里,不在 asyncio 事件循环上)。

------------------------------------------------------------------------------
2026-10-23 修复:系统代理把自动登录请求带离本地反代
------------------------------------------------------------------------------

现场(2026-10-20 20:24,``log/mitm-20261020-202416.log``):
``create_login`` 拦到了、auto 账号也在,3 秒后的 ``scan`` 却抛
``SSLCertVerificationError: unable to get local issuer certificate``。
mitmproxy 日志里**没有**对应的 ``client connect`` —— 说明请求根本没走
127.0.0.1:443,而是交给了别的进程(系统代理),拿到的是真实 mkey 证书,
再拿本地 mitm CA 去校验,必然失败。

根因是 ``requests`` 默认 ``trust_env=True``:它会读 ``HTTPS_PROXY`` 等环境
变量,**在 Windows 上还会读注册表里的系统代理**(Clash / v2ray 一类工具
默认就开)。这个请求按设计必须命中 hosts 重定向后的本地反代,任何代理都
是错误的中转。本文件因此:

1. 每个请求用 ``trust_env=False`` 的独立 Session,并显式 ``proxies={}``;
2. 拨号前先确认目标主机解析到回环地址,不满足就抛可读的 ``AutoLoginError``
   (而不是等一次诡异的 TLS 失败);
3. TLS / 连接失败时把底层库的异常翻译成「该怎么修」的一句话;
4. ``probe_chain()`` 给 GUI / addon 做自检:只握手、不发 HTTP,验证
   ``127.0.0.1:443`` 出示的证书确实由当前数据目录的 mitm CA 签发。
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import requests

from svs_autologin import paths
from svs_autologin.errors import AutoLoginError

#: hosts 重定向的目标主机(mkey 的正式域名,不是 CNAME 别名)。
RELAY_HOST = "service.mkey.163.com"

#: 本地反向代理监听的端口(run_mitmdump.py 的默认值)。
RELAY_PORT = 443

#: 只有解析到这些地址,请求才算「走本地反代」。
LOOPBACK = frozenset({"127.0.0.1", "::1"})


def ca_path() -> Path:
    """当前数据目录的 mitm CA 证书路径(每次调用现算)。

    开发形态 ``~/.mitmproxy``;安装形态 ``<数据目录>\\certs``(paths.confdir)。
    现算而不是模块级常量:测试要能通过 ``SVS_DATA_DIR`` 切换数据目录。
    """
    return paths.confdir() / "mitmproxy-ca-cert.pem"


#: 兼容旧引用(tests/test_phase5_paths_wiring.py 断言过这个名字)。
_MITM_CA = ca_path()


# --------------------------------------------------------------------------
# 拨号前的本地链路检查
# --------------------------------------------------------------------------

def _resolve(host: str, port: int = RELAY_PORT) -> List[str]:
    """``getaddrinfo`` 的薄封装(测试注入同名 callable)。"""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def loopback_problem(
    url: str,
    *,
    resolver: Optional[Callable[[str, int], Sequence[str]]] = None,
) -> Optional[str]:
    """目标主机是否解析到回环地址;是返回 None,否则返回一句可读的问题。

    这是「请求会不会被 hosts 带进本地反代」的唯一判据。解析失败也按问题
    返回(不抛),调用方决定怎么呈现。
    """
    host = urlsplit(url).hostname
    if not host:
        return f"无法从 URL 里取到主机名:{url!r}"

    resolve = resolver or _resolve
    try:
        addresses = list(resolve(host, RELAY_PORT))
    except OSError as exc:
        return (
            f"解析 {host} 失败:{exc}。"
            f"自动登录请求必须命中 hosts 条目「127.0.0.1 {RELAY_HOST}」。"
        )

    bad = sorted({addr for addr in addresses if addr not in LOOPBACK})
    if bad:
        return (
            f"{host} 解析到 {', '.join(bad)},不是 127.0.0.1。"
            f"自动登录请求必须经过本地反向代理(hosts 条目:127.0.0.1 {RELAY_HOST});"
            f"现在它会直连真实服务器,再用本地 mitm CA 校验就必然失败。"
            f"请在 GUI 点「自检」修复 hosts(或重跑 tools\\install.ps1)。"
        )
    return None


def _verify_for(verify: Any) -> Any:
    """把 ``qrcode.verify`` 解析成 requests 的 verify 参数。

    ``True`` 时**必须**有本地 CA 文件:静默回落到 certifi 会把「证书缺失」
    伪装成一次 TLS 失败,现场只剩一行 CERTIFICATE_VERIFY_FAILED。
    """
    if verify is True:
        path = ca_path()
        if not path.exists():
            raise AutoLoginError(
                f"本地 mitm CA 证书缺失:{path}。"
                f"没有它就无法校验本地反向代理的证书;请重跑安装器(install.ps1)"
                f"或确认数据目录正确。"
            )
        return str(path)
    return verify


def _first_line(text: str, limit: int = 300) -> str:
    stripped = (text or "").strip()
    line = stripped.splitlines()[0] if stripped else ""
    return line if len(line) <= limit else line[:limit] + "…"


def _ssl_message(exc: BaseException) -> str:
    return (
        "自动登录请求的 TLS 校验失败 —— 请求没有命中本地反向代理,"
        "或反代用的不是当前数据目录的 mitm CA。"
        "常见原因:① 系统代理/环境代理(Clash、v2ray 等)接管了请求;"
        "② hosts 条目缺失;③ 代理进程来自另一个安装目录(CA 不同)。"
        "处置:关闭系统代理后重试;在 GUI 点「自检」;必要时重启代理。"
        f"原始错误:{type(exc).__name__}: {_first_line(str(exc))}"
    )


def _connection_message(exc: BaseException) -> str:
    return (
        f"无法连接本地反向代理 127.0.0.1:{RELAY_PORT}({type(exc).__name__}: "
        f"{_first_line(str(exc))})。代理可能没有启动、启动失败,或端口被占用 —— "
        f"先在 GUI 点「启动」并确认状态是「运行中」。"
    )


# --------------------------------------------------------------------------
# 请求
# --------------------------------------------------------------------------

def _default_session() -> requests.Session:
    """必须绕开一切环境/系统代理的 Session。

    ``trust_env = False`` 同时关掉 ``HTTPS_PROXY`` 与 Windows 注册表代理
    (requests 经 ``urllib.request.getproxies()`` 读后者)。这不是可选项:
    请求的终点是 hosts 重定向后的 127.0.0.1:443,被任何代理中转都会拿到
    真实服务器证书,校验必然失败。
    """
    session = requests.Session()
    session.trust_env = False
    session.proxies = {}
    return session


def make_transport(
    *,
    session_factory: Optional[Callable[[], Any]] = None,
    resolver: Optional[Callable[[str, int], Sequence[str]]] = None,
) -> "Transport":
    """构造一个符合 ``qrcode_login.Transport`` 签名的可调用对象。

    两个注入点只服务测试(不联网、不碰真实解析器):
    ``session_factory`` 返回带 ``request()`` 的会话;``resolver(host, port)``
    返回地址列表。
    """
    factory = session_factory or _default_session

    def transport(
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[Any] = None,
        headers: Optional[dict] = None,
        verify: Any = True,
        timeout: float = 10.0,
    ) -> Tuple[int, Optional[Any]]:
        if not url.startswith("https://"):
            raise ValueError(f"relay_transport 只允许 https:// 目标,收到 {url!r}")

        problem = loopback_problem(url, resolver=resolver)
        if problem:
            raise AutoLoginError(problem)

        verify_value = _verify_for(verify)
        session = factory()
        try:
            try:
                response = session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify_value,
                    timeout=timeout,
                    # 三保险:会话本身已 trust_env=False 且 proxies={};
                    # 这里再显式传一次,避免将来有人换成共享 Session。
                    proxies={},
                    # 不跟随重定向:跳到非回环主机就等于绕开本地反代。
                    allow_redirects=False,
                )
            except requests.exceptions.SSLError as exc:
                raise AutoLoginError(_ssl_message(exc)) from exc
            except requests.exceptions.ConnectionError as exc:
                raise AutoLoginError(_connection_message(exc)) from exc
            except requests.exceptions.Timeout as exc:
                raise AutoLoginError(
                    f"本地反向代理响应超时(>{timeout}s):"
                    f"{_first_line(str(exc))} —— 检查代理日志。"
                ) from exc
            except OSError as exc:
                # requests 读不了自定义 CA bundle 时抛的是裸 OSError,
                # 不是 SSLError;qrcode.verify 配了坏路径会走到这里。
                raise AutoLoginError(
                    f"请求失败:{type(exc).__name__}: {_first_line(str(exc))}。"
                    f"如果这不是网络错误,检查配置 qrcode.verify 指向的 CA 文件是否存在。"
                ) from exc

            try:
                parsed = response.json()
            except ValueError:
                parsed = None
            return response.status_code, parsed if isinstance(parsed, dict) else None
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()

    return transport


# --------------------------------------------------------------------------
# 自检探针(GUI / addon 共用;只碰回环地址)
# --------------------------------------------------------------------------

def probe_listening(port: int = RELAY_PORT, timeout: float = 1.0) -> bool:
    """127.0.0.1:port 是否已有监听(不发送任何字节)。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        return sock.connect_ex(("127.0.0.1", port)) == 0
    finally:
        sock.close()


def probe_chain(
    *,
    ca_file: Optional[Path] = None,
    host: str = RELAY_HOST,
    port: int = RELAY_PORT,
    timeout: float = 3.0,
) -> Tuple[bool, str]:
    """只做一次 TLS 握手,验证本地反代出示的证书链。

    成功 = 127.0.0.1:port 上的监听者用 ``<数据目录>\\certs`` 的 mitm CA 签了
    ``host`` 的叶子证书。失败时返回一句可读的原因(不抛)。

    不发 HTTP 请求、不连外网:握手完立即关闭。
    """
    ca = Path(ca_file) if ca_file is not None else ca_path()
    if not ca.exists():
        return False, f"本地 mitm CA 证书不存在:{ca}"

    try:
        context = ssl.create_default_context(cafile=str(ca))
    except (ssl.SSLError, OSError) as exc:
        return False, f"无法加载 CA 证书 {ca}:{_first_line(str(exc))}"
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as exc:
        return False, f"无法连接 127.0.0.1:{port}:{exc}(代理未启动或端口被占用)"

    try:
        tls = context.wrap_socket(raw, server_hostname=host)
    except ssl.SSLError as exc:
        raw.close()
        return False, (
            f"TLS 校验失败:{_first_line(str(exc))}。"
            f"本地反代出示的证书不是由 {ca} 签发的(是不是读了另一个数据目录的 CA?)"
        )
    except OSError as exc:
        raw.close()
        return False, f"TLS 握手失败:{_first_line(str(exc))}"
    try:
        cert = tls.getpeercert() or {}
        subject = dict(item for rdn in cert.get("subject", ()) for item in rdn)
        return True, f"{tls.version()} {subject.get('commonName', host)}"
    finally:
        tls.close()
