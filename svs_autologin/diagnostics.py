"""诊断包(阶段 5):远程排错的一键导出。

用户拿到别人的机器上的问题时,让对方点 GUI 的「导出诊断包」、把 zip
发回来 —— 里面的信息要足够定位绝大多数故障,同时**零凭据**(C4):

* 三份日志(gui/proxy/当前 mitm)全文 —— 写入方(RotatingFileHandler +
  RedactingFilter)已按脱敏纪律产出,这里原样收;
* config.local.json **redact 后**的副本 —— token/log_key 类字段值全部
  打码后才进包;
* 账号摘要:每条**只留** uuid / name / login_channel / user_info.id /
  last_login_time。``login_info.code``(扫码码值,可复用)与
  ``ext_info.extra_unisdk_data``(内嵌 sessionid)整段排除;
* 工具版本、主机平台、系统状态探针结果(hosts 条目 / CA 在信任库 /
  443 占用 / pid 状态)。

系统探针(probes)以回调字典注入:默认实现读 hosts 文件与证书库、
探端口 —— 都是本地只读。测试注入假探针,逻辑层保持零网络
(conftest 的 no_network fixture 同一套纪律)。
"""

from __future__ import annotations

import json
import logging
import platform
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from svs_autologin import __version__
from svs_autologin.accounts import load_accounts
from svs_autologin.config import load_app_config
from svs_autologin.logtail import current_mitm_log
from svs_autologin.logging_setup import redact

log = logging.getLogger(__name__)

#: 账号摘要的白名单字段:不进白名单的一律不进包(默认拒绝,不是默认放行)。
ACCOUNT_SUMMARY_FIELDS = (
    "uuid",
    "name",
    "login_channel",
    "user_id",
    "last_login_time",
)

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_NEEDLE = "service.mkey.163.com"

Probes = Mapping[str, Callable[[], Any]]


def hosts_entry() -> Optional[str]:
    """hosts 里命中的第一条目标域名行(不在注释里),没有返回 None。

    返回**整行**而不是 bool:自检还要判断它指向哪 —— 旧安装留下的
    ``1.2.3.4 service.mkey.163.com`` 会让游戏直连真实服务器,比「没有条目」
    更难排查。
    """
    try:
        for line in Path(HOSTS_PATH).read_text(encoding="utf-8", errors="replace").splitlines():
            if HOSTS_NEEDLE in line and not line.strip().startswith("#"):
                return line.strip()
    except OSError:
        pass
    return None


def root_thumbprints() -> List[str]:
    """本机「受信任的根证书颁发机构」里每张证书的 SHA-1 指纹(小写 hex)。

    优先用标准库 ``ssl.enum_certificates("ROOT")``:它直接读系统证书库,
    比拉起 PowerShell 快一个数量级,而且不会因为控制台代码页/转义层出问题。
    读不到(非 Windows、权限异常)时退回 PowerShell。

    返回**全部**根证书而不是只挑 mitmproxy 的:自检要按指纹确认「安装目录
    这一张」被信任了,只看到「某张 mitmproxy 在库里」是假阳性 —— 开发机上
    同时存在 ``~/.mitmproxy`` 的旧 CA 是常态。
    """
    try:
        import hashlib
        import ssl

        return [
            hashlib.sha1(der).hexdigest()
            for der, _encoding, _trust in ssl.enum_certificates("ROOT")
        ]
    except (ImportError, OSError, AttributeError):
        pass

    import subprocess  # 只读探针,本地 powershell;不属出站客户端禁式

    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ChildItem Cert:\\LocalMachine\\Root | Select-Object -ExpandProperty Thumbprint)"],
            capture_output=True, timeout=15, check=False,
        )
        return [ln.strip().lower() for ln in out.stdout.decode("utf-8", errors="replace").splitlines() if ln.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def default_probes() -> Dict[str, Callable[[], Any]]:
    """真机默认探针集合(全部本地只读)。"""
    import subprocess  # 只读探针,本地 powershell;不属出站客户端禁式

    def ca_in_root() -> List[str]:
        """根证书库里 mitmproxy 主题的指纹(诊断包展示用;自检走按指纹比对)。"""
        try:
            import ssl

            hits = []
            for der, _encoding, _trust in ssl.enum_certificates("ROOT"):
                if b"mitmproxy" in der:
                    import hashlib

                    hits.append(hashlib.sha1(der).hexdigest())
            if hits:
                return hits
        except (ImportError, OSError, AttributeError):
            pass

        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like '*mitmproxy*' } | Select-Object -ExpandProperty Thumbprint)"],
                capture_output=True, timeout=15, check=False,
            )
            return [ln.strip() for ln in out.stdout.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        except (OSError, subprocess.TimeoutExpired):
            return []

    def port_443_busy() -> bool:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            return s.connect_ex(("127.0.0.1", 443)) == 0
        finally:
            s.close()

    return {
        "hosts_entry": hosts_entry,
        "mitm_ca_thumbprints_in_root": ca_in_root,
        "port_443_busy": port_443_busy,
    }


def _account_summaries(accounts_path: Path) -> List[Dict[str, Any]]:
    """白名单即机制:每条记录**只**取 ``ACCOUNT_SUMMARY_FIELDS`` 列出的键
    (缺的键空串),不进白名单的字段到不了 zip —— 常量与构造同源,
    加字段改一处,不存在「常量说一套、代码摘另一套」的漂移。"""
    summaries: List[Dict[str, Any]] = []
    for account in load_accounts(accounts_path):
        source = {
            "uuid": account.uuid,
            "name": account.name,
            "login_channel": account.channel_name,
            "user_id": account.user_info.get("id", ""),
            "last_login_time": account.last_login_time,
        }
        summaries.append({field: source.get(field, "") for field in ACCOUNT_SUMMARY_FIELDS})
    return summaries


def collect_bundle(data_dir: Path, probes: Optional[Probes] = None) -> Path:
    """把诊断包写进 ``<data_dir>/export/``,返回 zip 路径。

    任何单个组件的失败(缺文件、坏 JSON)只跳过该组件并记日志 ——
    诊断包的价值在「把*能拿到的*发回来」,不能因为 accounts.json 坏了
    就连日志都拿不到。
    """
    data = Path(data_dir)
    export = data / "export"
    export.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_path = export / f"svs-diagnostics-{stamp}.zip"

    probe_results: Dict[str, Any] = {}
    for name, probe in (probes if probes is not None else default_probes()).items():
        try:
            probe_results[name] = probe()
        except Exception as exc:  # 探针挂了不能拖垮整包
            probe_results[name] = f"<probe failed: {exc}>"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        def add_text(name: str, text: str) -> None:
            zf.writestr(name, text)

        # 1. 日志:三份,有什么带什么
        log_dir = data / "log"
        for log_name in ("gui.log", "proxy.log"):
            p = log_dir / log_name
            if p.exists():
                try:
                    zf.write(p, arcname=f"log/{log_name}")
                except OSError:
                    pass
        mitm = current_mitm_log(log_dir)
        if mitm is not None:
            try:
                zf.write(mitm, arcname=f"log/{mitm.name}")
            except OSError:
                pass

        # 2. config 脱敏副本
        try:
            config = load_app_config(data / "config.local.json", validate=False)
            add_text("config.redacted.json", json.dumps(redact(config), indent=2, ensure_ascii=False))
        except Exception as exc:
            add_text("config.error.txt", f"{exc}")

        # 3. 账号摘要(白名单字段)
        try:
            add_text(
                "accounts.summary.json",
                json.dumps(_account_summaries(data / "accounts.json"), indent=2, ensure_ascii=False),
            )
        except Exception as exc:
            add_text("accounts.error.txt", f"{exc}")

        # 4. 系统状态 + 版本
        add_text(
            "system.json",
            json.dumps(
                {
                    "version": __version__,
                    "python": platform.python_version(),
                    "machine": platform.machine(),
                    "os": platform.platform(),
                    "probes": probe_results,
                },
                indent=2,
                ensure_ascii=False,
            ),
        )

    log.info("诊断包已导出:%s", zip_path)
    return zip_path
