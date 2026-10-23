"""错误类型。

参考实现的两个可读性灾难(见 开发侧架构拆解 缺陷 1、缺陷 2):

1. log_key 查不到 -> ``AttributeError: 'NoneType' object has no attribute 'encode'``,
   三个栈帧之外才知道发生了什么。本项目用 ``MissingLogKeyError`` 替代,
   消息里必须带 game_id 与下一步指引。
2. 所有自定义错误都挂在 ``AutoLoginError`` 下,调用方 ``except AutoLoginError``
   即可拿到一个能直接展示给使用者的消息。
"""


class AutoLoginError(Exception):
    """本项目所有可预期错误的基类。消息应当可以直接展示给使用者。"""


class MissingLogKeyError(AutoLoginError):
    """目标游戏在本地缓存与游戏目录中都查不到 log_key。

    消息约定(tests/test_cloudres_lookup.py 是契约):

    * 必须包含**短** game_id;
    * 必须包含字符串 ``log_key``;
    * 必须指向 阶段 0 取证文档 / 阶段 0 —— 告诉使用者这个 key
      无法推导、无法借用,只能按取证手册自己拿。
    """


class SigningError(AutoLoginError):
    """签名环节的前置条件不满足(例如 key 为空字符串)。"""
