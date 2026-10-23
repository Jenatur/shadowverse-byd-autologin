"""首跑知情同意(docs/constraints.md C6,阶段 5 落地)。

同意过一次就落盘(版本 + 时间戳),之后不再打扰;拒绝 = 不落盘,
GUI 直接退出。文件是普通 JSON —— 它不含任何敏感信息,可读性优先。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]

CONSENT_FILE = "consent.json"


def consent_path(data_dir: PathLike) -> Path:
    return Path(data_dir) / CONSENT_FILE


def has_consented(data_dir: PathLike) -> bool:
    """True = 当前版本已同意过。文件缺失/损坏/未同意都算 False。"""
    p = consent_path(data_dir)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and bool(data.get("agreed"))


def mark_consented(data_dir: PathLike, version: str) -> Path:
    """记录同意(版本 + 时间戳),返回文件路径。

    目录不存在则创建 —— 首跑时数据目录可能还是空的(GUI 的日志目录
    先行创建,同意文件通常紧随其后)。
    """
    p = consent_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {"agreed": True, "version": version, "timestamp": int(time.time())},
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return p
