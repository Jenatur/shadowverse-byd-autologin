"""日志与凭据脱敏。

两个职责:

1. ``redact()``:在日志边界把敏感字段的值替换为 ``***``。
   access_key / sessionid / token 是凭据,任何一条进了日志文件,
   就等于把账号明文写盘(docs/constraints.md C4)。
2. ``configure()``:统一初始化。日志文件必须用**绝对路径** ——
   参考实现用相对路径,日志落到哪个目录取决于从哪里启动程序
   (开发侧架构拆解 §1 的坑),本项目不重蹈。
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from typing import Any, Iterable, List, Mapping, Optional, Sequence

# 与 spec/app-config.schema.json log.redact 的 default 一致。
DEFAULT_REDACT_KEYS = ("access_key", "sessionid", "token", "log_key", "password", "sessdata")

REDACTED = "***"

_configured = False


def redact(
    obj: Any,
    keys: Optional[Iterable[str]] = None,
) -> Any:
    """递归地把 ``keys`` 中(大小写不敏感)命中的字段的值替换为 ``***``。

    返回**新结构**,不修改入参;list/tuple 逐项处理,其余标量原样返回。
    """
    sensitive = {k.lower() for k in (keys if keys is not None else DEFAULT_REDACT_KEYS)}
    return _redact(obj, sensitive)


def _redact(obj: Any, sensitive: frozenset) -> Any:
    if isinstance(obj, Mapping):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in sensitive:
                out[k] = REDACTED
            else:
                out[k] = _redact(v, sensitive)
        return out
    if isinstance(obj, (list, tuple)):
        seq = [_redact(v, sensitive) for v in obj]
        return seq if isinstance(obj, list) else tuple(seq)
    return obj


class RedactingFilter(logging.Filter):
    """挂在 handler 上的脱敏过滤器:对 dict 形态的 msg/args 过一遍 redact。"""

    def __init__(self, keys: Optional[Sequence[str]] = None) -> None:
        super().__init__()
        self.keys = tuple(keys) if keys is not None else DEFAULT_REDACT_KEYS

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if isinstance(record.msg, Mapping):
            record.msg = redact(record.msg, self.keys)
        elif isinstance(record.args, tuple) and any(
            isinstance(a, Mapping) for a in record.args
        ):
            record.args = tuple(
                redact(a, self.keys) if isinstance(a, Mapping) else a for a in record.args
            )
        elif isinstance(msg, str):
            # 兜底:消息里嵌了敏感 k=v 时把值打码(尽力而为,键集合有限)。
            for key in self.keys:
                token = key + "="
                if token in msg:
                    head, _, tail = msg.partition(token)
                    value, sep, rest = tail.partition(" ")
                    msg = f"{head}{token}{REDACTED}{sep}{rest}"
            record.msg = msg
            record.args = None
        return True


def configure(
    level: str = "INFO",
    log_file: Optional[str] = None,
    redact_keys: Optional[Sequence[str]] = None,
    force: bool = False,
    *,
    max_bytes: int = 2 * 1024 * 1024,
    backup_count: int = 5,
) -> List[logging.Handler]:
    """初始化根 logger;返回挂上的 handler 列表(便于测试后清理)。

    ``log_file`` 必须是绝对路径(schema 的默认值即是);相对路径会被拒绝,
    避免重演参考实现「日志跟着 CWD 跑」的问题。

    文件 handler 走轮转(2MB × 5);``sys.stderr`` 为 None 时跳过流
    handler —— pythonw(无控制台)下 stderr 是 None,StreamHandler 会在
    emit 时抛错。
    """
    global _configured
    if _configured and not force:
        return []

    if log_file is not None and not os.path.isabs(os.path.expanduser(log_file)):
        raise ValueError(
            f"log file must be an ABSOLUTE path, got {log_file!r} "
            "(the reference implementation's relative log path is the bug this replaces)"
        )

    root = logging.getLogger()
    root.setLevel(level.upper())

    filt = RedactingFilter(redact_keys)
    handlers: List[logging.Handler] = []

    if sys.stderr is not None:
        stream = logging.StreamHandler(sys.stderr)
        stream.addFilter(filt)
        handlers.append(stream)

    if log_file:
        handlers.append(
            attach_file_handler(
                log_file, redact_keys=redact_keys,
                max_bytes=max_bytes, backup_count=backup_count,
            )
        )

    for h in list(root.handlers):  # 幂等:清掉上次 configure 挂的
        root.removeHandler(h)
    for h in handlers:
        root.addHandler(h)

    _configured = True
    return handlers


def attach_file_handler(
    log_file: str,
    redact_keys: Optional[Sequence[str]] = None,
    *,
    max_bytes: int = 2 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Handler:
    """往根 logger **追加**一个轮转文件 handler(带脱敏),返回它。

    与 ``configure()`` 的区别:configure 是「接管根 logger」(先清空全部
    既有 handler),本函数只加不动 —— 供 mitmdump 进程里的 addon 用:
    那个进程的根 logger 上挂着 mitmproxy 自己的 handler,清掉它们等于
    弄哑 mitmdump 的控制台/流量日志。

    一个进程一个日志文件是使用纪律(Windows 上 RotatingFileHandler 的
    轮转 rename 在另一个进程持有同名句柄时会失败):GUI 进程写 gui.log,
    代理进程写 proxy.log,mitmdump 的 stdout 落单独的 mitm-*.log。
    """
    if not os.path.isabs(os.path.expanduser(log_file)):
        raise ValueError(
            f"log file must be an ABSOLUTE path, got {log_file!r} "
            "(the reference implementation's relative log path is the bug this replaces)"
        )
    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    fh.addFilter(RedactingFilter(redact_keys))
    logging.getLogger().addHandler(fh)
    return fh
