"""log_key 两级查找:本地缓存 → 游戏目录。

参考实现的查找顺序(开发侧架构拆解 配置层):

1. ``cache.json['data']`` —— 一个 list,每行是「一个游戏 × 一个渠道」的配置对象,
   同一游戏多渠道行的 ``log_key`` 完全相同(key 属于游戏,不属于渠道包)。
2. ``dynamic_game_catalog`` —— 兜底。

参考实现两级都 miss 时返回 ``None``,这个 ``None`` 一路漂到 calcSign 才炸出
``AttributeError: 'NoneType' object has no attribute 'encode'``。
本项目在这里抛 ``MissingLogKeyError``,消息带 game_id 和取证指引。

匹配规则(与参考实现一致,由 tests/test_cloudres_lookup.py 固定):

* 只按 ``game_id`` 索引;``package_name`` 恰好像 ID 也不许命中;
* ``log_key`` 为 ``''`` / ``None`` / 字段缺失,一律视为没有;
* 查找用**短** game_id(本函数内部先归一化,调用方传原始 ID 也行,
  但契约上调用方应当传短 ID)。
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from svs_autologin.errors import MissingLogKeyError
from svs_autologin.game_id import get_short_game_id


def _usable(key: Any) -> bool:
    """与参考实现的 `item.get(key) not in ('', None)` 等价:空串、None 都不算数。"""
    return key not in ("", None)


def lookup_log_key(
    cache: Optional[Mapping[str, Any]],
    catalog: Any,
    game_id: str,
) -> str:
    """查出目标游戏的 log_key;两级都 miss 时抛 ``MissingLogKeyError``。

    ``cache``:形如 ``{"data": [{"game_id": "g37", "log_key": ...}, ...]}`` 的映射。
    ``catalog``:有 ``get_cloud_config(short_game_id) -> Optional[dict]`` 的对象。
    """
    short = get_short_game_id(game_id or "")

    # 第 1 级:本地缓存。命中即返回,不咨询 catalog(顺序由测试固定)。
    for entry in ((cache or {}).get("data") or []):
        if entry.get("game_id") == short:
            key = entry.get("log_key")
            if _usable(key):
                return key
            # game_id 对上了但 key 不可用:同一游戏多渠道行共享同一个 key,
            # 继续扫剩余行没有意义,直接落到第 2 级。

    # 第 2 级:动态游戏目录。
    if catalog is not None:
        cfg = catalog.get_cloud_config(short)
        if isinstance(cfg, Mapping):
            key = cfg.get("log_key")
            if _usable(key):
                return key

    raise MissingLogKeyError(
        f"log_key for game {short!r} not found in the local cache or the game "
        f"catalog; the key cannot be derived or borrowed from another game "
        f"(27 games -> 27 keys, one-to-one, zero reuse). Capture it locally "
        f"first - see 阶段 0 取证文档 (阶段 0 / phase 0) - then store it in "
        f"config.local.json under log_key.{short!r}."
    )
