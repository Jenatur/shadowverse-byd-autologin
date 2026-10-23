"""工具配置的装载、校验、保存。

数据模型是 spec/app-config.schema.json。这里做**无依赖的轻量校验**
(不引入 jsonschema):覆盖 schema 的 required / pattern / enum / 范围约束,
足够把「复制 example 后忘了填哪」这类错误在启动时拦下来。

约定(spec/app-config.schema.json 顶注):以 ``_`` 开头的键是注释,
loader 先剥离再校验 —— 所以重度注释的 config.example.json 剥离后
仍是 schema 的合法实例。``save_app_config`` 写盘前同样剥离。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Union

from svs_autologin.errors import AutoLoginError

# 与 schema 对齐的约束(刻意不用正则:动态执行禁令按字面匹配,标准库的
# regex 预编译函数会被同一规则误伤) --------------------------------------------

_LOG_KEY_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _is_private_host(host: str) -> bool:
    """loopback / localhost / RFC1918(docs/constraints.md C2,schema 的 pattern)。"""
    if host in ("127.0.0.1", "::1", "localhost"):
        return True
    parts = host.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)


def _is_valid_log_key(value: str) -> bool:
    """32 个 [A-Za-z0-9_-] 字符(schema log_key 的 pattern)。"""
    return len(value) == 32 and all(c in _LOG_KEY_ALPHABET for c in value)

ALLOWED_TOP_LEVEL = {
    "listen", "upstream", "auto", "games", "log_key",
    "device", "log", "confirm", "network", "ca", "toggles", "qrcode",
}

REQUIRED_TOP_LEVEL = ("listen", "upstream", "auto", "games")


class ConfigError(AutoLoginError):
    """配置文件不合法。消息里带字段路径与原因。"""


# --------------------------------------------------------------------------
# 剥离 '_' 注释键(递归;list 内的 dict 也剥)
# --------------------------------------------------------------------------

def strip_comments(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {k: strip_comments(v) for k, v in obj.items() if not (isinstance(k, str) and k.startswith("_"))}
    if isinstance(obj, list):
        return [strip_comments(v) for v in obj]
    return obj


# --------------------------------------------------------------------------
# 校验
# --------------------------------------------------------------------------

def _check(cond: bool, path: str, why: str) -> None:
    if not cond:
        raise ConfigError(f"{path}: {why}")


def validate_app_config(config: Mapping[str, Any]) -> None:
    """按 spec/app-config.schema.json 的约束做轻量校验,不合法抛 ConfigError。"""
    for key in REQUIRED_TOP_LEVEL:
        _check(key in config, key, "required section missing (see spec/app-config.schema.json)")
    unknown = set(config) - ALLOWED_TOP_LEVEL
    _check(not unknown, "<root>", f"unknown top-level key(s): {sorted(unknown)}")

    listen = config.get("listen") or {}
    _check(
        isinstance(listen.get("host"), str) and _is_private_host(listen["host"]),
        "listen.host",
        "must be loopback or a private LAN address (docs/constraints.md C2)",
    )
    for port_key in ("http_port", "https_port"):
        port = listen.get(port_key)
        _check(
            isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535,
            f"listen.{port_key}",
            "must be an integer in [1, 65535]",
        )

    upstream = config.get("upstream") or {}
    allow = upstream.get("allow")
    _check(
        isinstance(allow, list) and allow and all(isinstance(h, str) and h for h in allow),
        "upstream.allow",
        "must be a non-empty list of hostnames (docs/constraints.md C1)",
    )
    _check(isinstance(upstream.get("verify_tls"), bool), "upstream.verify_tls", "must be a boolean")

    for key, value in (config.get("log_key") or {}).items():
        _check(
            isinstance(value, str) and _is_valid_log_key(value),
            f"log_key.{key}",
            "must be 32 chars of [A-Za-z0-9_-] (phase-0 capture, docs/constraints.md C4)",
        )

    network = config.get("network")
    if network is not None:
        mode = network.get("mode") if isinstance(network, Mapping) else None
        _check(
            mode in (None, "emulator_proxy", "emulator_hosts", "host_nrpt"),
            "network.mode",
            "must be one of emulator_proxy / emulator_hosts / host_nrpt",
        )

    qrcode = config.get("qrcode")
    if qrcode is not None:
        _check(isinstance(qrcode, Mapping), "qrcode", "must be an object")
        if isinstance(qrcode, Mapping):
            base_url = qrcode.get("base_url")
            _check(
                base_url is None or (isinstance(base_url, str) and base_url.startswith("https://")),
                "qrcode.base_url",
                "must be an https:// URL - the two mkey endpoints are TLS only, "
                "and a plaintext base would silently downgrade the scan/confirm calls",
            )
            # verify 可以是 true/false(自签 CA 场景)或一个 CA bundle 路径。
            verify = qrcode.get("verify")
            _check(
                verify is None or isinstance(verify, (bool, str)),
                "qrcode.verify",
                "must be a boolean or a path to a CA bundle",
            )
            timeout = qrcode.get("timeout")
            _check(
                timeout is None
                or (isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and timeout > 0),
                "qrcode.timeout",
                "must be a positive number of seconds",
            )

    ca = config.get("ca")
    if ca is not None:
        target = ca.get("install_target") if isinstance(ca, Mapping) else None
        _check(
            target in (None, "emulator_system", "emulator_user", "host_system", "host_user"),
            "ca.install_target",
            "must be one of emulator_system / emulator_user / host_system / host_user",
        )


# --------------------------------------------------------------------------
# 装载 / 保存
# --------------------------------------------------------------------------

def load_app_config(
    path: Union[str, Path],
    *,
    validate: bool = True,
) -> Dict[str, Any]:
    """读入 JSON 配置,剥离 ``_`` 注释键;``validate=True`` 时做轻量校验。

    返回剥离后的新 dict,不修改磁盘文件。文件不存在/不是合法 JSON 抛 ConfigError。
    """
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p} (copy config.example.json to config.local.json first)")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{p}: not valid JSON - {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{p}: top level must be a JSON object")
    config = strip_comments(raw)
    if validate:
        validate_app_config(config)
    return config


def save_app_config(config: Mapping[str, Any], path: Union[str, Path]) -> Path:
    """把配置写盘(indent=2,ensure_ascii=False)。``_`` 注释键同样被剥离。"""
    p = Path(path)
    clean = strip_comments(dict(config))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(clean, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return p
