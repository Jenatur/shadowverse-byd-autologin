"""svs_autologin - 本地自动登录工具的契约实现包(PLAN.md 阶段 1)。

分层(与 开发侧架构拆解 对应,但零外联):

    intercept   编排层:状态机 + 改写规则(纯逻辑,不含网络)
    sauth       票据层:SAUTH 报文与 unisdk 结果组装(纯数据构造)
    uni         票据层:签名请求封装(传输由外部注入,见 uni.py 文档)
    sign        票据层:HMAC-SHA256 签名(开发侧金标向量 金标)
    cloudres    配置层:log_key 两级查找(cache -> catalog),查不到显式报错
    game_id     配置层:'aecXXXXX-g-YY' -> 'YY' 短 ID 提取
    rollback    网络层配套:可回滚栈(任何一步失败都不阻断其余回滚)
    config      工具配置装载/校验/保存(剥离 '_' 注释键)
    logging_setup 日志与凭据脱敏
    errors      错误类型(AutoLoginError 为根)

本包自身**不发起任何网络连接**(docs/constraints.md C1):
出站传输一律通过调用方注入的 transport 回调完成,见 uni.post_signed_data。
"""

from svs_autologin.errors import AutoLoginError, MissingLogKeyError, SigningError
from svs_autologin.game_id import get_short_game_id
from svs_autologin.sign import calc_sign, get_sign_src

__version__ = "0.2.2"

__all__ = [
    "AutoLoginError",
    "MissingLogKeyError",
    "SigningError",
    "get_short_game_id",
    get_sign_src.__name__,
    calc_sign.__name__,
]
