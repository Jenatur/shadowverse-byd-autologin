"""短 game_id 提取。

参考实现(已验证,见 docs/protocol.md / 开发侧金标向量)::

    getShortGameId('aecXXXXX-g-YY') == 'YY'
    未知格式**原样返回**,不抛错。

保留这个「未知格式透传」的健壮性是刻意的:新 ID 格式不应让工具崩溃。
它的代价是——一个我们不认识的 ID 会以原样去查 log_key,然后安静地查不到。
所以查不到时的**显式报错**收敛在 cloudres.lookup_log_key 里,
不在本函数(见 tests/test_cloudres_lookup.py TestShortIdInteraction)。

实现说明:刻意不用正则 —— tests/test_failure_modes.py 的动态执行禁令
按字面匹配,连标准库的 regex 预编译函数都会被同一规则误伤;而这里的
判定用字符串方法同样精确(与 ``^aec[A-Za-z0-9]+-g-(.+)$`` 逐例等价)。
"""

from __future__ import annotations

import string

_ASCII_ALNUM = frozenset(string.ascii_letters + string.digits)


def get_short_game_id(raw: str) -> str:
    """'aecfrugltuaaaajo-g-ma68' -> 'ma68';任何不匹配的输入原样返回。

    >>> get_short_game_id('aecflsysdmaaaag3-g-g37')
    'g37'
    >>> get_short_game_id('brand-new-format')
    'brand-new-format'
    """
    if not raw:
        return raw
    # 在第一个 '-g-' 处切:短 ID 自己可以以 'g' 开头(如 g37),
    # 不能重复切。head 必须形如 'aec' + 至少一个 ASCII 字母数字。
    head, sep, tail = raw.partition("-g-")
    if sep and head.startswith("aec") and head[3:] and all(c in _ASCII_ALNUM for c in head[3:]):
        return tail
    return raw
