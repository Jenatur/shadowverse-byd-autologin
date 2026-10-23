"""签名请求封装(post_signed_data)。

协议细节(docs/protocol.md §3.3):URL 模板、固定 User-Agent、X-Client-Sign 头。

**零外联设计决策**(docs/constraints.md C1,tests/test_no_egress.py 强制):
本包自身**不发起任何 HTTP 请求**——源码树里不允许出现出站 HTTP 客户端调用。
真实的出站传输由调用方注入的 ``sender`` 回调承担(生产环境里由拦截层的
中转通道提供:请求作为「游戏流量中转」的一部分被转发,而不是工具自己拨号)。
阶段 3 接上真实渠道时,由编排层传入 sender;在此之前不带 sender 调用会在
签名完成后立刻抛 ``AutoLoginError``,而不是默默碰网。

错误契约(tests/test_failure_modes.py defect 1):log_key 拿不到时必须抛
``MissingLogKeyError`` 且消息带 game_id —— 参考实现在这里死于
``AttributeError: 'NoneType' object has no attribute 'encode'``。
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping, Optional

from svs_autologin.cloudres import lookup_log_key
from svs_autologin.errors import AutoLoginError
from svs_autologin.game_id import get_short_game_id
from svs_autologin.sign import calc_sign

UNI_SAUTH_URL_TEMPLATE = "https://mgbsdk.matrix.netease.com/{game_id}/sdk/uni_sauth"

# 参考实现里硬编码的固定 UA,逐字照抄(docs/protocol.md §3.3)。
FIXED_USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 12; M2102K1AC Build/V417IR)"

# sender: (url, body, headers, verify_tls) -> 解析后的 JSON dict。
Sender = Callable[..., Any]


def post_signed_data(
    *,
    data: Mapping[str, Any],
    game_id: str,
    cache: Optional[Mapping[str, Any]] = None,
    catalog: Any = None,
    log_key: Optional[str] = None,
    sender: Optional[Sender] = None,
    verify_tls: bool = True,
    need_custom_encode: bool = False,
) -> Any:
    """签名并(经由注入的 sender)POST 到 ``/<短ID>/sdk/uni_sauth``,返回解析结果。

    key 的解析顺序:显式传入的 ``log_key`` 优先(非空时);
    否则走 ``lookup_log_key(cache, catalog, 短ID)`` —— 查不到抛
    ``MissingLogKeyError``,消息带 game_id 与取证指引,**绝不**带着
    空 key 往下走。
    """
    short = get_short_game_id(game_id or "")
    if not log_key:
        log_key = lookup_log_key(cache, catalog, short)  # 可能抛 MissingLogKeyError

    url = UNI_SAUTH_URL_TEMPLATE.format(game_id=short)
    body = json.dumps(data)  # 逐字节参与签名:空格、键序都不能再动

    sign = calc_sign(url, "POST", body, log_key)
    headers = {
        "X-Client-Sign": sign,
        "Content-Type": "application/json",
        "User-Agent": FIXED_USER_AGENT,
    }

    if sender is None:
        raise AutoLoginError(
            "no transport configured: pass `sender=` (the relay layer owns the "
            "outbound path - this package never dials out on its own, "
            "docs/constraints.md C1)"
        )
    return sender(url=url, body=body, headers=headers, verify_tls=verify_tls)
