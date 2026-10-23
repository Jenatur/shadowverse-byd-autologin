"""SAUTH 报文与 unisdk 结果组装。

字段、顺序、序列化细节全部来自「实际执行参考实现导出」的观测
(开发侧金标向量 的 buildSAUTH / unisdk_result 两节),
tests/test_sauth_payload.py 是契约。

与参考实现的一个**刻意差异**(docs/constraints.md C1 / docs/protocol.md §1.1):
参考实现在这里查公网 IP,本项目改为由调用方通过 ``ip=`` 传入,
本模块没有任何网络行为。
"""

from __future__ import annotations

import base64
import json
import random
from typing import Any, Dict, Mapping, Optional

# --------------------------------------------------------------------------
# 常量:与参考实现逐字对齐(来源见 开发侧金标向量)
# --------------------------------------------------------------------------

DEFAULT_SDK_VERSION = "5.9.6"
DEFAULT_GV = "157"
DEFAULT_GVN = "1.5.80"
DEFAULT_CV = "a1.5.0"

# 参考实现 fakeDevice.json 的内容(字段顺序即 JSON 输出顺序)。
DEFAULT_DEVICE: Dict[str, Any] = {
    "device_model": "M2102K1AC",
    "os_name": "android",
    "os_ver": "12",
    "udid": "775ae8FEF020e038",
    "app_ver": "157",
    "imei": "233040993303313",
    "country_code": "CN",
    "is_emulator": 0,
    "is_root": 0,
    "oaid": "",
}

# realname 串是逐字照抄的(含空格),不是我们 json.dumps 出来的。
REALNAME_JSON = '{"realname_type": 0, "age": 22}'

_SN_ALPHABET = "0123456789abcdefABCDEF"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _client_login_sn() -> str:
    """16 位十六进制,大小写混合(参考实现形态,如 '54Eea57c0DDEEFd6')。"""
    return "".join(random.choice(_SN_ALPHABET) for _ in range(16))


def _step() -> str:
    """10 位十进制数字串。"""
    return str(random.randint(10**9, 10**10 - 1))


def _step2() -> str:
    """9 位十进制数字串。"""
    return str(random.randint(10**8, 10**9 - 1))


def build_sauth(
    *,
    account: Mapping[str, Any],
    game_id: str,
    device: Mapping[str, Any],
    ip: str,
    custom_data: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """组装 SAUTH 主体,恰好 18 个字段,顺序固定(见 UNI_BODY_FIELD_ORDER)。

    ``ip`` 必须由调用方传入(参考实现在这里查公网 IP —— 本项目禁止,
    见模块 docstring)。随机字段(client_login_sn/step/step2)每次调用重新生成。
    """
    login_resp = account.get("loginResp") or {}
    channel = account.get("login_channel", "")
    sdk_version = account.get("bili_sdk_ver") or DEFAULT_SDK_VERSION
    udid = device.get("udid", "")

    aim_info = json.dumps(
        {"tz": "+0800", "tzid": "Asia/Shanghai", "aim": ip, "country": "CN"},
        separators=(",", ":"),
        ensure_ascii=False,
    )

    data: Dict[str, Any] = {
        "gameid": game_id,                 # 短 ID
        "login_channel": channel,
        "app_channel": channel,
        "platform": "ad",
        "sdkuid": login_resp.get("uid", ""),
        "udid": udid,
        "sessionid": login_resp.get("access_key", ""),
        "sdk_version": sdk_version,
        "is_unisdk_guest": 0,              # int 0,不是 False、不是 '0'
        "ip": ip,                          # 调用方给的本地值,零外联
        "aim_info": aim_info,              # 字符串化 JSON,不是嵌套对象
        "source_app_channel": channel,
        "source_platform": "ad",
        "client_login_sn": _client_login_sn(),
        "step": _step(),
        "step2": _step2(),
        "hostid": 0,                       # int 0
        "sdklog": json.dumps(device, ensure_ascii=False),  # 字符串化 JSON
    }
    if custom_data:
        data.update(custom_data)
    return data


def build_unisdk_result(
    *,
    account: Mapping[str, Any],
    short_game_id: str,
    uni_body: Mapping[str, Any],
    device: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """组装游戏消费的最终 13 键结果(docs/protocol.md §4.3)。

    键顺序敏感(插入顺序即 JSON 键序),四个易错点全部按实测照抄:

    1. ``pay_channel`` 是渠道名,不是空串;
    2. ``extra_data`` 是空字符串,不是 None/'{}'/json.dumps 结果;
    3. ``extra_unisdk_data`` 是 JSON **字符串**,不是嵌套对象;
    4. ``SAUTH_STR`` 是**单层** base64,解码即 k=v 表单串。
    """
    if device is None:
        device = DEFAULT_DEVICE

    login_resp = account.get("loginResp") or {}
    channel = account.get("login_channel", "")
    sdk_version = uni_body.get("sdk_version") or account.get("bili_sdk_ver") or DEFAULT_SDK_VERSION
    sdk_udid = device.get("udid", "")

    # json_data:前 4 个固定字段 + 18 个 SAUTH 字段追加(顺序即最终顺序)。
    json_data: Dict[str, Any] = {
        "extra_data": None,          # 注意是 None
        "get_access_token": "1",     # '1',不是 1
        "sdk_udid": sdk_udid,
        "realname": REALNAME_JSON,
    }
    json_data.update(uni_body)

    # str_data:SAUTH_STR 的内容 = json_data 的 k=v 表单串,username 追加最后。
    str_data = dict(json_data)
    str_data["username"] = account.get("name", "")
    form = "&".join(f"{k}={v}" for k, v in str_data.items())  # 无 URL 编码

    extra_unisdk_data = json.dumps(
        {
            "SAUTH_STR": _b64(form),
            "SAUTH_JSON": _b64(json.dumps(json_data, ensure_ascii=False)),
            "realname": REALNAME_JSON,
        },
        ensure_ascii=False,
    )

    access_key = login_resp.get("access_key", "")
    return {
        "user_id": login_resp.get("uid", ""),
        "token": _b64(access_key),       # 单层 base64
        "login_channel": channel,
        "udid": sdk_udid,
        "app_channel": channel,
        "sdk_version": sdk_version,
        "jf_game_id": short_game_id,
        "pay_channel": channel,          # 渠道名,不是 ''
        "extra_data": "",                # 空字符串
        "extra_unisdk_data": extra_unisdk_data,  # JSON 字符串
        "gv": DEFAULT_GV,
        "gvn": DEFAULT_GVN,
        "cv": DEFAULT_CV,
    }
