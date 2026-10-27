"""自动登录开工前自检:把「账号已记录、但登录不动」变成一句能照做的话。

这个模块是 2026-10-23 接手时加的。现场证据(`logs/`)说明失败点根本不在
扫码/确认的报文上,而在**请求有没有走本地反代**:

* 2026-10-19 21:23 一次完整自动登录成功(scan 200 → confirm 200 → 游戏
  自己 exchange_token 200);
* 2026-10-20 20:24 同一条链路在 scan 就抛 ``CERTIFICATE_VERIFY_FAILED``,
  而 mitmproxy 日志里没有对应的 ``client connect`` —— 请求被系统代理带走,
  拿到真实服务器证书,再拿本地 mitm CA 校验。

这类问题在 GUI 上只表现为「二维码一直没人扫」,排错成本极高。所以自检把
四件事拆成独立、可解释的检查项:账号 / hosts / CA / 代理与 TLS 链。

**纯逻辑**:所有探针都由调用方注入(hosts 行、根证书指纹、端口、TLS 握手
结果、CA 文件路径)。本模块不碰网络、不起进程、不读系统证书库 —— 它只
把「已经观测到的事实」翻译成结果。真正的探针在 ``tools/`` 侧(GUI 与
addon 组装),测试可以完全离线地喂任意组合。
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

from svs_autologin.accounts import Account, find_by_uuid

#: hosts 里必须存在的那一行(主机名部分)。
HOSTS_NEEDLE = "service.mkey.163.com"

#: 该行必须指向的地址。
HOSTS_EXPECTED_IP = "127.0.0.1"


@dataclass(frozen=True)
class Check:
    """一项自检结果。``fatal`` = 自动登录必然不工作(不是「可能有问题」)。"""

    key: str
    title: str
    ok: bool
    fatal: bool
    detail: str
    fix: str = ""

    @property
    def severity(self) -> str:
        if self.ok:
            return "ok"
        return "error" if self.fatal else "warn"


def pem_thumbprint(path: Path) -> Optional[str]:
    """PEM 证书的 SHA-1 指纹(小写 hex);读不到/不是证书返回 None。

    与 Windows 根证书库 ``X509Certificate2.Thumbprint`` 同一口径,可以直接
    和 ``ssl.enum_certificates("ROOT")`` 里每一项的 SHA-1 比较。
    """
    try:
        text = Path(path).read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    if "-----BEGIN CERTIFICATE-----" not in text:
        return None
    try:
        der = ssl.PEM_cert_to_DER_cert(text)
    except ValueError:
        return None
    return hashlib.sha1(der).hexdigest()


def check_config(error: Optional[BaseException]) -> Check:
    if error is None:
        return Check("config", "配置文件", True, False, "config.local.json 可读、结构合法")
    return Check(
        "config",
        "配置文件",
        False,
        True,
        f"config.local.json 读不出来:{error}",
        "确认数据目录里的 config.local.json 是合法 JSON;或删掉它,"
        "重跑安装器生成默认配置。",
    )


def check_auto_target(
    config: Mapping[str, Any],
    accounts: Iterable[Account],
    game_id: str,
) -> Check:
    """``auto.<game_id>`` 是否指向一条完整可用的账号记录。"""
    auto = (config.get("auto") or {})
    target = str(auto.get(game_id) or "").strip()
    if not target:
        return Check(
            "auto_target",
            "自动登录账号",
            False,
            True,
            f"auto.{game_id} 是空的 —— 账号可能已经记录,但没有任何账号被设为默认,"
            f"所以 create_login 不会触发自动扫码。",
            "在账号列表里点一下要用的账号(变成 [默认]),或点「添加账号」重新扫一次。",
        )

    account = find_by_uuid(list(accounts), target)
    if account is None:
        return Check(
            "auto_target",
            "自动登录账号",
            False,
            True,
            f"auto.{game_id} 指向的账号 {target!r} 不在 accounts.json 里。",
            "重新扫码记录一次,或把 auto 指向现有账号。",
        )

    user = account.user_info
    if not user.get("id") or not user.get("token"):
        return Check(
            "auto_target",
            "自动登录账号",
            False,
            True,
            f"账号 {target!r} 缺少 user_info.id / token,凭据不完整。",
            "删除该账号并重新扫码授权。",
        )

    return Check(
        "auto_target",
        "自动登录账号",
        True,
        False,
        f"{account.name}({account.uuid}),登录渠道 {account.channel_name or '?'}",
    )


def check_hosts(hosts_line: Optional[str]) -> Check:
    """hosts 里是否有把目标域名指向 127.0.0.1 的有效行。

    ``hosts_line`` 是探针给的**命中的那一行**(没有则 None)。只检查「有没有
    这个域名」不够:旧安装可能留下 ``1.2.3.4 service.mkey.163.com`` 这种行,
    它会让游戏直连真实服务器,登录窗照样弹,但工具完全看不见。
    """
    if not hosts_line:
        return Check(
            "hosts",
            "hosts 重定向",
            False,
            True,
            f"hosts 里没有 {HOSTS_NEEDLE} 条目,游戏的登录流量不会经过本地代理。",
            f"运行安装器(tools\\install.ps1)添加「{HOSTS_EXPECTED_IP} {HOSTS_NEEDLE}」,"
            f"或在 GUI 点「自检」按提示修复。",
        )

    tokens = hosts_line.replace("\t", " ").split()
    if HOSTS_EXPECTED_IP not in tokens[:1]:
        return Check(
            "hosts",
            "hosts 重定向",
            False,
            True,
            f"hosts 条目没有指向 {HOSTS_EXPECTED_IP}:{hosts_line!r}",
            f"把该行改成「{HOSTS_EXPECTED_IP} {HOSTS_NEEDLE}」,再重启代理。",
        )

    return Check("hosts", "hosts 重定向", True, False, hosts_line)


def check_ca(ca_file: Path, root_thumbprints: Sequence[str]) -> Check:
    """数据目录里的 mitm CA 是否就是系统根证书库信任的那一张。

    GUI 旧实现只检查「根证书库里有没有任意 mitmproxy 证书」。开发机上通常
    同时存在 ``~/.mitmproxy`` 的旧 CA 和安装目录的新 CA,前者在库里不代表
    后者被信任 —— 游戏的 SDK 会拒绝代理出示的叶子证书,表现成登录窗
    打不开/网络错误。这里按**指纹**比对,才算证明。
    """
    ca_file = Path(ca_file)
    if not ca_file.exists():
        return Check(
            "ca",
            "mitm CA 证书",
            False,
            True,
            f"证书文件不存在:{ca_file}",
            "重跑安装器(install.ps1)生成并导入 CA。",
        )

    thumbprint = pem_thumbprint(ca_file)
    if thumbprint is None:
        return Check(
            "ca",
            "mitm CA 证书",
            False,
            True,
            f"证书文件不是合法的 PEM 证书:{ca_file}",
            "删除 certs 目录后重跑安装器重新生成。",
        )

    trusted = {str(t).strip().lower() for t in root_thumbprints if str(t).strip()}
    if thumbprint not in trusted:
        return Check(
            "ca",
            "mitm CA 证书",
            False,
            True,
            f"指纹 {thumbprint[:16]}… 不在系统根证书库 —— 游戏的 TLS 校验会失败。",
            "以管理员身份重跑安装器(install.ps1);只导入别的 mitmproxy CA 不管用。",
        )

    return Check(
        "ca", "mitm CA 证书", True, False, f"已在根证书库(指纹 {thumbprint[:16]}…)"
    )


def check_proxy(listening: bool, port: int = 443) -> Check:
    if listening:
        return Check("proxy", "本地反向代理", True, False, f"127.0.0.1:{port} 已在监听")
    return Check(
        "proxy",
        "本地反向代理",
        False,
        False,
        f"127.0.0.1:{port} 没有监听 —— 代理还没启动。",
        "点「启动」后再启动游戏。",
    )


# --------------------------------------------------------------------------
# 账号凭据有效期(2026-10-27)
# --------------------------------------------------------------------------

def _b64_any(text: str) -> bytes:
    """标准/URL-safe/百分号编码的 base64 都试。

    ``SAUTH_JSON`` 在真实记录里是**百分号编码**的 base64(尾部 ``%3D%3D``),
    先 unquote 再解码;JWT 段则是 URL-safe base64(``-``/``_``)。
    """
    text = (text or "").strip().strip('"')
    if not text:
        raise ValueError("empty base64")
    candidates = [text]
    unquoted = urllib.parse.unquote(text)
    if unquoted != text:
        candidates.append(unquoted)
    for candidate in candidates:
        padded = candidate + "=" * (-len(candidate) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return decoder(padded, validate=True)
            except Exception:
                continue
    raise ValueError("not valid base64")


def credential_expiry(account: Account) -> Tuple[Optional[datetime], str]:
    """从账号记录里取 B站 access_token 的 JWT 过期时间(本地时区)。

    链路:``ext_info.extra_unisdk_data``(JSON 串)→ ``SAUTH_JSON``(base64)
    → ``{"access_token": "<JWT>"}`` → JWT payload 的 ``exp``。

    为什么需要它:2026-10-27 的真机现场是 **mkey 的 confirm 照常 200、
    exchange_token 照常 200**,但游戏紧接着提示「登录已失效,请重新扫码登录」。
    原因是记录里的 B站 access_token 已于 10-23 20:25 过期 —— mkey 不校验它,
    游戏服务器校验。本地自检只看 hosts/CA/代理/TLS 是发现不了的。

    解析失败返回 ``(None, 原因)``,不抛。
    """
    raw = account.ext_info.get("extra_unisdk_data") or ""
    if not raw:
        return None, "账号记录里没有 ext_info.extra_unisdk_data"
    try:
        extra = json.loads(raw)
    except (TypeError, ValueError) as exc:
        return None, f"extra_unisdk_data 不是 JSON:{exc}"
    sauth_json = (extra or {}).get("SAUTH_JSON") or ""
    if not sauth_json:
        return None, "extra_unisdk_data 里没有 SAUTH_JSON"
    try:
        payload = json.loads(_b64_any(sauth_json).decode("utf-8"))
        token = str(payload.get("access_token") or "")
        if not token:
            return None, "SAUTH_JSON 里没有 access_token"
        info = json.loads(_b64_any(token.split(".")[1]))
        exp = int(info["exp"])
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return datetime.fromtimestamp(exp, tz=timezone.utc).astimezone(), ""


def check_credential(
    account: Optional[Account],
    *,
    now: Optional[datetime] = None,
    warn_hours: float = 24.0,
) -> Check:
    """账号凭据是否还在有效期内。过期 = 自动登录必然被游戏拒绝(致命)。"""
    title = "账号凭据有效期"
    if account is None:
        return Check(
            "credential", title, False, False,
            "未检查:没有可用的默认账号。",
            "先添加账号并设为默认。",
        )
    exp, problem = credential_expiry(account)
    if exp is None:
        return Check(
            "credential", title, False, False,
            f"无法解析有效期({problem})。",
            "如果登录后提示「登录已失效」,重新扫码一次即可。",
        )
    now = now or datetime.now().astimezone()
    if exp <= now:
        days = (now - exp).total_seconds() / 86400
        return Check(
            "credential",
            title,
            False,
            True,
            f"已于 {exp:%Y-%m-%d %H:%M} 过期(约 {days:.1f} 天前)—— "
            f"mkey 仍会接受扫码确认,但游戏会提示「登录已失效,请重新扫码登录」。",
            "在「添加账号」重新扫码一次,并设为默认账号。",
        )
    remain_hours = (exp - now).total_seconds() / 3600
    if remain_hours <= warn_hours:
        return Check(
            "credential", title, False, False,
            f"将于 {exp:%Y-%m-%d %H:%M} 过期(剩 {remain_hours:.1f} 小时)。",
            "尽快重新扫码,否则登录会被游戏拒绝。",
        )
    return Check(
        "credential", title, True, False,
        f"有效至 {exp:%Y-%m-%d %H:%M}(剩 {remain_hours / 24:.1f} 天)",
    )


def check_chain(chain: Optional[tuple]) -> Check:
    """``chain`` = 探针返回的 ``(ok, detail)``;None = 没跑(代理未启动)。"""
    if chain is None:
        return Check(
            "chain",
            "TLS 链路",
            False,
            False,
            "未检查:代理没有在运行。",
            "启动代理后点「自检」复查。",
        )
    ok, detail = bool(chain[0]), str(chain[1])
    if ok:
        return Check("chain", "TLS 链路", True, False, detail)
    return Check(
        "chain",
        "TLS 链路",
        False,
        True,
        detail,
        "先点「重启代理」;仍失败时关闭系统代理(Clash/v2ray 等)再试,"
        "并确认代理读的是本安装目录的 CA。",
    )


def run_checks(
    *,
    config: Mapping[str, Any],
    accounts: Iterable[Account],
    game_id: str,
    ca_file: Path,
    hosts_line: Optional[str],
    root_thumbprints: Sequence[str],
    listening: bool,
    chain: Optional[tuple] = None,
    config_error: Optional[BaseException] = None,
    port: int = 443,
) -> List[Check]:
    """按「越靠前越根本」的顺序跑完全部检查。"""
    accounts = list(accounts)
    target = str((config.get("auto") or {}).get(game_id) or "").strip()
    account = find_by_uuid(accounts, target) if target else None
    return [
        check_config(config_error),
        check_auto_target(config, accounts, game_id),
        check_credential(account),
        check_hosts(hosts_line),
        check_ca(ca_file, root_thumbprints),
        check_proxy(listening, port),
        check_chain(chain),
    ]


def fatal_problems(checks: Iterable[Check]) -> List[Check]:
    """所有会让自动登录必然失败的检查项。"""
    return [c for c in checks if not c.ok and c.fatal]


def pending(checks: Iterable[Check]) -> List[Check]:
    """非致命但不通过的检查项(例如代理还没启动)。"""
    return [c for c in checks if not c.ok and not c.fatal]


def ready(checks: Iterable[Check]) -> bool:
    """没有致命问题 = 自动登录的本地条件已齐。"""
    return not fatal_problems(checks)


def format_report(checks: Iterable[Check]) -> str:
    """多行报告(GUI 对话框 / 日志共用)。

    标记刻意用中文方括号而不是 ``✓`` / ``✗``:报告也会进 mitmdump 的
    stdout,那里按控制台代码页(中文 Windows 是 GBK)编码,Unicode 对勾会
    直接抛 ``UnicodeEncodeError``。日志是给人看的,不是给终端字体看的。
    """
    checks = list(checks)
    passed = sum(1 for c in checks if c.ok)
    failed = len(checks) - passed
    head = f"自动登录自检:{passed}/{len(checks)} 项通过"
    if failed:
        head += f",{failed} 项未通过"
    lines = [head, ""]
    for check in checks:
        mark = "[通过]" if check.ok else ("[失败]" if check.fatal else "[待办]")
        lines.append(f"{mark} {check.title}:{check.detail}")
        if not check.ok and check.fix:
            lines.append(f"   处置:{check.fix}")
    return "\n".join(lines)


def auto_summary(
    config: Mapping[str, Any],
    accounts: Iterable[Account],
    game_id: str,
) -> str:
    """状态栏用的一句话:自动登录现在到底会不会触发。"""
    target = str((config.get("auto") or {}).get(game_id) or "").strip()
    if not target:
        return "未设置默认账号 —— 自动登录不会触发"
    account = find_by_uuid(list(accounts), target)
    if account is None:
        return f"默认账号 {target} 不在账号表中"
    if not account.user_info.get("id") or not account.user_info.get("token"):
        return f"默认账号 {target} 凭据不完整,需要重新扫码"
    exp, _problem = credential_expiry(account)
    if exp is not None:
        now = datetime.now().astimezone()
        if exp <= now:
            return f"默认账号 {target} 凭据已于 {exp:%m-%d %H:%M} 过期 —— 需重新扫码"
        if (exp - now).total_seconds() <= 86400:
            return f"已启用 —— {account.name}(凭据 {exp:%m-%d %H:%M} 到期)"
    return f"已启用 —— {account.name}({account.uuid})"
