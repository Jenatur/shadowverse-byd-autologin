"""请求签名(HMAC-SHA256)。

全部行为由 开发侧金标向量 定义,tests/test_signature.py 是契约。
这一层若不全绿,后面所有「签名对不上」的排查都是在浪费时间的猜测。

⚠️ 反直觉的坑(实测确认,别改):**主机名不参与签名**。
参与的是「url 去掉 '://' 之后,从第一个 '/' 到结尾」的部分;
url 里没有 '/' 时,主机名整段被丢掉,原串就是 METHOD + body。
端口跟着主机名一起被丢弃。
"""

from __future__ import annotations

import hashlib
import hmac

from svs_autologin.errors import MissingLogKeyError, SigningError


def get_sign_src(method: str, url: str, body: str) -> str:
    """构造签名原串:``METHOD.upper() + path_part + body``(body 逐字节原样拼接)。

    >>> get_sign_src('POST', 'https://mgbsdk.matrix.netease.com/g37/sdk/uni_sauth', 'D1')
    'POST/g37/sdk/uni_sauthD1'
    >>> get_sign_src('GET', 'https://hostonly', 'D3')
    'GETD3'
    """
    host_part = ""
    stripped = url.replace("://", "")
    i = stripped.find("/")
    if i != -1:
        host_part = stripped[i:]  # 从第一个 '/' 到结尾(注意不是 [:i])
    return method.upper() + host_part + body


def calc_sign(url: str, method: str, body: str, log_key: str) -> str:
    """HMAC-SHA256(key, get_sign_src(...)),64 位小写十六进制。

    参数顺序与参考实现的 calcSign(url, method, body, key) 一致。
    key 为假值时抛错——本项目的硬性要求(开发侧架构拆解 缺陷 1):
    绝不允许 ``None.encode()`` 这种死法。
    """
    if not log_key:
        # 正常流程下 lookup_log_key/post_signed_data 会先带着 game_id 抛
        # MissingLogKeyError;这里兜底,防止调用方绕过查找直接传入空 key。
        raise MissingLogKeyError(
            "log_key is empty; cannot sign the request "
            "(capture it first - see 阶段 0 取证文档, 阶段 0 / phase 0)"
        )
    try:
        src = get_sign_src(method, url, body)
        return hmac.new(log_key.encode(), src.encode(), hashlib.sha256).hexdigest()
    except (AttributeError, TypeError) as exc:
        raise SigningError(f"signing failed for url {url!r}: {exc}") from exc
