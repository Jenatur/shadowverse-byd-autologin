"""模拟扫码 / 模拟确认:把预存的渠道账号「喂」给 mkey 的二维码会话。

协议来自参考实现 ``channelmgr.ChannelManager.simulate_scan`` /
``simulate_confirm`` 的反汇编(2026-10-04),配合阶段 2 的实测端点
(开发侧取证记录)。两个端点都在 ``service.mkey.163.com``:

    GET  /mpay/api/qrcode/scan?uuid=..&login_channel=..&...      → 告诉 mkey「这个码被扫了」
    POST /mpay/api/qrcode/confirm_login   body: k=v&k=v&...       → 确认授权

之后游戏自己的 ``qrcode/query`` 轮询看到 ``status: 2``,发起 ``exchange_token``,
SAUTH 数据由那一步的响应内嵌(**PC 侧没有 Android 式的 uni_sauth**,见
开发侧取证记录)。

**零外联**(docs/constraints.md C1):本模块不拨号。出站经调用方注入的
``transport`` 完成,与 ``uni.post_signed_data`` 的 ``sender=`` 同一套设计。
生产用的 transport 属于中转层;本模块只保证报文构造与流程编排是逐字段对的。

与参考实现的两处**刻意差异**,都是为了这个项目自己的错误契约:

1. 失败**抛** ``AutoLoginError``,不返回 ``False`` —— 调用方 ``except
   AutoLoginError`` 就能拿到一句能直接给使用者看的话(``errors.py`` 的约定)。
   参考实现返回 False + 顺手清全局标志,失败原因散在日志里。
2. 不碰任何全局状态,也不写账号文件;``last_login_time`` 的更新由调用方决定。

``scan`` 有一个 ``code == 1424`` 的重试:create_login 的 query 里带的是**完整**
game_id(``aecfrugltuaaaajo-g-ma68``),而 mkey 要的是短的那侧。服务端会把
正确值放在 ``resp['game']['id']`` 里回给我们,照原样重发一次即可。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from svs_autologin.accounts import Account
from svs_autologin.errors import AutoLoginError
from svs_autologin.sauth import DEFAULT_CV, DEFAULT_GV, DEFAULT_GVN

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://service.mkey.163.com"
SCAN_PATH = "/mpay/api/qrcode/scan"
CONFIRM_PATH = "/mpay/api/qrcode/confirm_login"

#: scan 用完整 game_id 时服务端回的「发烧平台游戏 id」提示码。
GAME_ID_MISMATCH_CODE = 1424

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

#: ``transport(method, url, *, params, data, headers, verify, timeout) -> (status, json)``
#: ``json`` 在响应体不是 JSON(或空)时为 None。
Transport = Callable[..., Tuple[int, Optional[Any]]]


# --------------------------------------------------------------------------
# 报文构造(纯函数,逐字段可测)
# --------------------------------------------------------------------------

def build_scan_params(*, channel_name: str, qr_uuid: str, game_id: str) -> Dict[str, Any]:
    """``scan`` 的 query 参数。插入顺序即参考实现 ``BUILD_CONST_KEY_MAP`` 的顺序。

    ``login_channel`` / ``app_channel`` / ``pay_channel`` 三个都取同一个渠道名 ——
    参考实现三处都写的是 ``channel.channel_name``。跨渠道扫码能成立(阶段 2 实测:
    B站 App 扫官服 PC 包)说明 mkey 按渠道票据判定,不按这个字段。
    """
    return {
        "uuid": qr_uuid,
        "login_channel": channel_name,
        "app_channel": channel_name,
        "pay_channel": channel_name,
        "game_id": game_id,
        "gv": DEFAULT_GV,
        "gvn": DEFAULT_GVN,
        "cv": DEFAULT_CV,
    }


def build_confirm_body(*, unisdk_data: Mapping[str, Any], qr_uuid: str, game_id: str) -> str:
    """``confirm_login`` 的 body:``k=v`` 用 ``&`` 拼,**不做 URL 编码**。

    这是参考实现 ``_do_confirm`` 的原样行为(反汇编偏移 94-202:``'&'.join`` +
    ``f'{k}={v}'``),必须照抄:``requests`` 收到 ``data=<str>`` 是原样发出的,
    服务端也就按原样收。我们改成 ``urlencode`` 反而会换一套没验证过的编码。

    ⚠️ 代价:字段值里若含 ``&``,body 的字段边界会被它切断。``token`` 是
    base64,理论上有 ``+``/``/``/``=``(服务端显然是按第一个 ``=`` 切、且不做
    ``+``→空格 的还原,否则参考实现早就跑不通了),但 ``&`` 一定是坏的 ——
    所以这里只对 ``&`` 记一条警告,不擅自改编码。
    """
    data: Dict[str, Any] = dict(unisdk_data)
    data["uuid"] = qr_uuid
    data["game_id"] = game_id

    for key, value in data.items():
        if isinstance(value, str) and "&" in value:
            log.warning("confirm_login 字段 %s 的值里含 '&',body 字段边界会被切断", key)

    return "&".join(f"{k}={v}" for k, v in data.items())


# --------------------------------------------------------------------------
# 流程
# --------------------------------------------------------------------------

def simulate_scan(
    *,
    account: Account,
    qr_uuid: str,
    game_id: str,
    transport: Transport,
    base_url: str = DEFAULT_BASE_URL,
    verify: Any = True,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """模拟扫码 → 模拟确认,成功返回 ``confirm_login`` 的响应体。

    ``game_id`` 传 create_login query 里那个**完整** id;服务端若回 1424,
    用 ``resp['game']['id']`` 重发一次(参考实现同款重试,只重试一次)。

    失败一律抛 ``AutoLoginError``,消息可直接展示。调用方(自动登录流程)
    拿到异常时负责收尾 —— 参考实现在这条路径上会顺手清全局标志,本项目把
    「清标志」收敛在 ``InterceptRules.finish_auto_login``,不在这里做。

    **第一次出站之前**先把账号记录过一遍(``get_uni_sdk_data``):``scan`` 一旦
    发出,服务端就把这个二维码标记成「已扫」,再拿一条缺 token 的记录去
    confirm 必然失败 —— 那等于把这次二维码会话白白烧掉。本地能判死的错,
    不要用一次网络往返去发现。

    ``params`` 在 1424 重试时**另起一个 dict**,不原地改:交给 transport 的
    对象不应该在它背后被改写(调用方可能已经把整个 params 存下来了)。
    """
    unisdk_data = account.get_uni_sdk_data(game_id)  # 见上:先做本地完整性检查
    params = build_scan_params(
        channel_name=account.channel_name, qr_uuid=qr_uuid, game_id=game_id
    )

    status, body = transport(
        "GET",
        base_url + SCAN_PATH,
        params=params,
        data=None,
        headers={"Accept": "*/*"},
        verify=verify,
        timeout=timeout,
    )
    resp = body if isinstance(body, Mapping) else {}

    if resp.get("code", -1) == GAME_ID_MISMATCH_CODE:
        corrected = (resp.get("game") or {}).get("id")
        if not corrected:
            raise AutoLoginError(
                f"scan 返回 {GAME_ID_MISMATCH_CODE} 但响应里没有 game.id,"
                f"无法纠正 game_id:{resp!r}"
            )
        log.info("scan:用服务端给出的 game_id 重发: %s", corrected)
        params = {**params, "game_id": corrected}
        status, body = transport(
            "GET",
            base_url + SCAN_PATH,
            params=params,
            data=None,
            headers={"Accept": "*/*"},
            verify=verify,
            timeout=timeout,
        )
        resp = body if isinstance(body, Mapping) else {}
        if resp.get("code", -1) == GAME_ID_MISMATCH_CODE:
            # 参考实现没有这道检查:它会拿着仍然冲突的 game_id 径直去做 confirm,
            # 失败原因就散在后续某一步里。这里只是把「重发也没救」这一点提前说清楚,
            # 成功路径的报文一个字节都没变。
            raise AutoLoginError(
                f"scan 重发后仍返回 {GAME_ID_MISMATCH_CODE}"
                f"(game_id={params['game_id']}),不再重试;响应 {resp!r}"
            )

    if status != 200:
        raise AutoLoginError(
            f"模拟扫码失败:HTTP {status}"
            + (f",响应 {resp!r}" if resp else "")
        )

    return simulate_confirm(
        account=account,
        qr_uuid=qr_uuid,
        game_id=params["game_id"],
        transport=transport,
        base_url=base_url,
        verify=verify,
        timeout=timeout,
        unisdk_data=unisdk_data,
    )


def simulate_confirm(
    *,
    account: Account,
    qr_uuid: str,
    game_id: str,
    transport: Transport,
    base_url: str = DEFAULT_BASE_URL,
    verify: Any = True,
    timeout: float = 10.0,
    unisdk_data: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """POST ``confirm_login``,返回响应体(成功时是 dict)。

    成功**不**改 ``account.last_login_time`` —— 那是调用方的落盘决策,
    本函数保持无副作用(见模块 docstring 差异 2)。

    ``unisdk_data`` 由 ``simulate_scan`` 预先算好传进来(它需要更早地做那次
    本地检查);单独调用本函数时留空,会现算(缺 id/token 时在这里抛)。
    """
    if unisdk_data is None:
        unisdk_data = account.get_uni_sdk_data(game_id)
    body = build_confirm_body(unisdk_data=unisdk_data, qr_uuid=qr_uuid, game_id=game_id)

    status, resp = transport(
        "POST",
        base_url + CONFIRM_PATH,
        params=None,
        data=body,
        headers={"Content-Type": FORM_CONTENT_TYPE, "Accept": "*/*"},
        verify=verify,
        timeout=timeout,
    )

    if status != 200:
        raise AutoLoginError(f"模拟确认失败:HTTP {status},响应 {resp!r}")

    if not isinstance(resp, Mapping):
        raise AutoLoginError(f"模拟确认返回的不是 JSON 对象:{resp!r}")

    # 阶段 4 补的检查,参考实现没有:成功时服务端回的是空对象 {}(2026-10-12
    # 实测),而失败可能以 200 + {code, reason} 的形态回来。不看 body 会把
    # 被拒绝当成成功,游戏干等二维码超时(约 3 分钟)才死心。
    code = resp.get("code")
    if code not in (None, 0, "0"):
        reason = resp.get("reason") or resp
        raise AutoLoginError(
            f"模拟确认被拒绝(code={code}):{reason!r}"
            " —— 账号凭据可能已失效,需要重新扫码授权"
        )

    log.info("模拟确认返回: %r", resp)
    return dict(resp)


def now() -> int:
    """``last_login_time`` 用的一秒精度时间戳(抽出来是为了可测)。"""
    return int(time.time())
