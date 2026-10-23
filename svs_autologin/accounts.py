"""渠道账号记录:读写、派生,以及 confirm_login 所需的 unisdk 载荷。

形态逐字段对齐参考实现的 ``channelmgr.channel`` / ``ChannelManager``
(2026-10-04 由 ``.pyc`` 反汇编确认,记录见 开发侧取证记录 的
「阶段 3 协议」一节):

* **记录** = ``{login_info, user_info, ext_info, device_info, create_time,
  last_login_time, name, uuid}``。落盘是**裸 JSON 数组** —— 与参考实现的
  ``channels.json`` 同形,用户可以直接把旧文件搬过来(spec/account.schema.json
  是契约)。
* ``uuid`` 缺省 = ``f"{login_info['login_channel']}-{login_info['code']}"``。
  注意**没有**渠道前缀:``bili-bilibili_sdk-100001`` 这种带前缀的 uuid 只出现在
  参考实现的手工导入路径,自动扫码路径产出的就是 ``bilibili_sdk-100001``。
* ``user_info`` 至少要有 ``id`` 与 ``token``,缺任一个参考实现抛
  ``ValueError('渠道登录信息不完整：缺少 user_id 或 token，请重新登录')``;
  本项目抛 ``AutoLoginError``,消息带 uuid,语义相同。

``token`` 是 **base64(sessionid)**,不是明文 sessionid —— 阶段 2 实测:
``exchange_token`` 响应里 ``user.token`` 解出来就是 Android 侧 ``uni_sauth``
响应里的那个 sessionid。

本模块**零外联**(docs/constraints.md C1):只做数据变换与本地文件读写。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from svs_autologin.errors import AutoLoginError
from svs_autologin.sauth import DEFAULT_CV, DEFAULT_GV, DEFAULT_GVN

# 参考实现 get_uniSdk_data 的字段顺序(BUILD_CONST_KEY_MAP 的字面顺序)。
# 顺序本身参与 confirm_login 的 body 拼接,不能当成普通 dict 随意重排。
UNI_SDK_FIELD_ORDER = (
    "user_id",
    "token",
    "login_channel",
    "udid",
    "app_channel",
    "sdk_version",
    "jf_game_id",
    "pay_channel",
    "extra_data",
    "extra_unisdk_data",
    "gv",
    "gvn",
    "cv",
)

# 参考实现 from_dict / __init__ 认的键,即记录的规范形态。
RECORD_KEYS = (
    "login_info",
    "user_info",
    "ext_info",
    "device_info",
    "create_time",
    "last_login_time",
    "name",
    "uuid",
)


def default_uuid(login_info: Mapping[str, Any]) -> str:
    """``f"{login_channel}-{code}"``;两个字段都缺就是 ``'-'``。

    参考实现在 ``uuid == ''`` 时才走这条推导,所以显式给了 uuid 的记录不会被改。
    """
    return f"{login_info.get('login_channel', '')}-{login_info.get('code', '')}"


class Account:
    """一条渠道账号记录。不可变意图:所有字段公开可读,改动请走显式方法。"""

    def __init__(
        self,
        login_info: Mapping[str, Any],
        user_info: Mapping[str, Any],
        ext_info: Optional[Mapping[str, Any]] = None,
        device_info: Optional[Mapping[str, Any]] = None,
        *,
        create_time: int = 0,
        last_login_time: int = 0,
        name: str = "",
        uuid: str = "",
    ) -> None:
        self.login_info: Dict[str, Any] = dict(login_info)
        self.user_info: Dict[str, Any] = dict(user_info)
        self.ext_info: Dict[str, Any] = dict(ext_info or {})
        self.device_info: Dict[str, Any] = dict(device_info or {})
        self.create_time = create_time
        self.last_login_time = last_login_time
        # 参考实现:name 为空时回落到 uuid,不是回落空串。
        self.uuid = uuid or default_uuid(self.login_info)
        self.name = name or self.uuid

    # ---------------------------------------------------------------- 构造

    @classmethod
    def from_record(cls, data: Mapping[str, Any]) -> "Account":
        """从落盘记录构造(参考实现 ``channel.from_dict`` 的语义)。

        ``create_time`` 缺省在参考实现里是**当前时间**;本项目缺省 0 —— 时间戳只
        用于展示,而测试与可重放性比它重要。传了就用传的。
        """
        return cls(
            login_info=data.get("login_info") or {},
            user_info=data.get("user_info") or {},
            ext_info=data.get("ext_info") or {},
            device_info=data.get("device_info") or {},
            create_time=data.get("create_time") or 0,
            last_login_time=data.get("last_login_time") or 0,
            name=data.get("name") or "",
            uuid=data.get("uuid") or "",
        )

    def to_record(self) -> Dict[str, Any]:
        """落盘形态。只写 RECORD_KEYS —— 参考实现的 ``__dict__`` dump 里多出来的
        ``exchange_data``/``channel_name``/``crossGames`` 是它的内部状态,
        ``from_dict`` 读不回来,写出去只会让文件对不上 schema。"""
        return {
            "login_info": self.login_info,
            "user_info": self.user_info,
            "ext_info": self.ext_info,
            "device_info": self.device_info,
            "create_time": self.create_time,
            "last_login_time": self.last_login_time,
            "name": self.name,
            "uuid": self.uuid,
        }

    # ---------------------------------------------------------------- 存取

    @property
    def channel_name(self) -> str:
        """渠道名,例如 ``bilibili_sdk``(参考实现 ``channel_name``)。"""
        return self.login_info.get("login_channel", "")

    def get_uni_sdk_data(self, game_id: str = "") -> Dict[str, Any]:
        """``simulate_confirm`` 的 body 素材,13 个字段,顺序固定。

        **``game_id`` 参数在参考实现里没有被使用** —— 调用方拿到返回值之后自己
        往里塞 ``uuid`` / ``game_id``(见 ``qrcode_login.build_confirm_body``)。
        保留这个参数是为了让调用形状与参考实现逐字一致,免得后来者以为漏了什么。

        两个必须照抄的怪点:

        1. ``sdk_version`` 取的是 ``src_jf_game_id`` —— 参考实现就是这么写的
           (反汇编偏移 298-344,连续两次 ``LOAD_FAST self.ext_info`` +
           ``get('src_jf_game_id')``)。看着像笔误,但它是**已验证可用**的行为,
           改掉等于换了一套没验证过的字段。
        2. ``extra_unisdk_data`` 直接透传 ``ext_info`` 里的原串,不在本地重新
           拼装 —— 与 ``sauth.build_unisdk_result`` 的做法不同,后者是从账号
           记录现算的。两条路都实现过,PC 侧走的是透传这条。
        """
        user_id = self.user_info.get("id")
        token = self.user_info.get("token")
        if not user_id or not token:
            raise AutoLoginError(
                f"渠道登录信息不完整(uuid={self.uuid}):缺少 user_info['id'] 或 "
                f"user_info['token'],需要重新扫码授权"
            )

        ext = self.ext_info
        return {
            "user_id": user_id,
            "token": token,
            "login_channel": ext.get("src_app_channel2", ""),
            "udid": ext.get("src_udid", ""),
            "app_channel": ext.get("src_app_channel", ""),
            "sdk_version": ext.get("src_jf_game_id", ""),  # 见 docstring 怪点 1
            "jf_game_id": ext.get("src_jf_game_id", ""),
            "pay_channel": ext.get("src_pay_channel", ""),
            "extra_data": "",
            "extra_unisdk_data": ext.get("extra_unisdk_data", ""),
            "gv": DEFAULT_GV,
            "gvn": DEFAULT_GVN,
            "cv": DEFAULT_CV,
        }


# --------------------------------------------------------------------------
# 从一次真实扫码的 exchange_token 响应派生记录
# --------------------------------------------------------------------------

def build_account(
    login_info: Mapping[str, Any],
    exchange_info: Mapping[str, Any],
) -> Account:
    """``qrcode/query`` 的 ``login_info`` + ``exchange_token`` 的响应体 → 记录。

    对应参考实现 ``ChannelManager.import_from_scan(login_info, exchange_info)``:
    ``user`` 必取,``ext_info`` / ``device`` 缺了就空 dict。

    ``login_info`` 是 ``qrcode/query`` 在 ``status == 2`` 时给出的那个对象,
    形如 ``{"code": "100001", "login_channel": "bilibili_sdk",
    "src_client_type": 1}`` —— ``uuid`` 就是从它的两个字段推出来的。
    """
    user = exchange_info.get("user")
    if not isinstance(user, Mapping) or not user:
        raise AutoLoginError(
            "exchange_token 响应里没有 user 对象,无法派发账号记录"
            "(开发侧取证记录「exchange_token 响应结构」)"
        )
    return Account(
        login_info=login_info,
        user_info=user,
        ext_info=exchange_info.get("ext_info") or {},
        device_info=exchange_info.get("device") or {},
    )


# --------------------------------------------------------------------------
# 落盘
# --------------------------------------------------------------------------

def load_accounts(path: Union[str, Path]) -> List[Account]:
    """读裸 JSON 数组。文件不存在 → 空列表(首次运行不是错误)。

    单条记录解析失败**不**让整体失败 —— 手工编辑过的文件里有一条坏记录,
    不应该把其余能用的账号一起赔进去;坏的那条记进 ``Account.skipped`` 的替代方案
    是直接跳过,这里选跳过。
    """
    p = Path(path)
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AutoLoginError(f"账号文件不是合法 JSON:{p} - {exc}") from exc
    if not isinstance(raw, list):
        raise AutoLoginError(f"账号文件顶层必须是 JSON 数组(参考实现同形):{p}")
    return [Account.from_record(item) for item in raw if isinstance(item, Mapping)]


def save_accounts(accounts: Iterable[Account], path: Union[str, Path]) -> Path:
    """写裸 JSON 数组,``ensure_ascii=False``(参考实现用 ``json.dump`` 默认参数,
    中文昵称会被转义;这里不转义,人读得懂比逐字节相像更重要)。

    **凭据落盘**(docs/constraints.md C4):文件权限按 0600 创建。Windows 上
    ``os.open`` 的 mode 只影响只读位;真正的收紧留给阶段 5 的安装脚本。
    调用方必须保证 ``path`` 在 .gitignore 覆盖的数据目录里。
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        [a.to_record() for a in accounts], indent=2, ensure_ascii=False
    ).encode("utf-8")

    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        os.replace(str(tmp), str(p))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    return p


def find_by_uuid(accounts: Iterable[Account], uuid: str) -> Optional[Account]:
    """按 uuid 找账号;找不到返回 None(调用方负责报「需要重新授权」)。"""
    for account in accounts:
        if account.uuid == uuid:
            return account
    return None


def is_same_account(left: Account, right: Account) -> bool:
    """同一个渠道账号的判定:``user_info['id']`` 相同,或 fallback 到 uuid 相同。

    两边都有 id 时**只**比 id:不同 id 就是不同账号,哪怕 uuid 撞了也不能并
    —— 并错了等于把一条记录的授权顶掉另一条。id 是主判据(参考实现就按它去重),
    任一条缺 id(手工编辑过的文件)时才退到 uuid,免得同一条记录被重复追加。
    """
    left_id = left.user_info.get("id")
    right_id = right.user_info.get("id")
    if left_id and right_id:
        return left_id == right_id
    return bool(left.uuid) and left.uuid == right.uuid


def upsert(accounts: List[Account], incoming: Account) -> Account:
    """按渠道账号去重后并入,返回留下的那条。

    对应参考实现 ``import_from_scan`` 的去重:同一渠道账号重复扫码时,**最新**
    那条记录继承旧记录的 ``name`` / ``uuid`` / ``last_login_time``(参考实现按
    ``last_login_time`` 倒序取第一条,即最近一次登录的那条),旧记录全部删除。
    这样 uuid 稳定,``auto.<game_id>`` 的指向不会因为一次重扫而失效。
    """
    same = [a for a in accounts if is_same_account(a, incoming)]
    if same:
        previous = max(same, key=lambda a: a.last_login_time or 0)
        incoming.name = previous.name or incoming.name
        incoming.uuid = previous.uuid or incoming.uuid
        incoming.last_login_time = previous.last_login_time or incoming.last_login_time
        for old in same:
            accounts.remove(old)
    accounts.append(incoming)
    return incoming


# --------------------------------------------------------------------------
# GUI 账号管理(阶段 5)
# --------------------------------------------------------------------------

def rename_account(accounts: List[Account], uuid: str, name: str) -> Account:
    """改显示名。找不到 uuid 抛 AutoLoginError(GUI 把它直接给用户看)。

    名字是纯 UI 概念:改它不影响 uuid,不影响 auto 指向。
    """
    account = find_by_uuid(accounts, uuid)
    if account is None:
        raise AutoLoginError(f"要改名的账号不在账号表中:{uuid!r}")
    account.name = name or account.uuid  # 空名回落 uuid(与 Account.__init__ 一致)
    return account


def delete_account(accounts: List[Account], uuid: str, config: Optional[Mapping[str, Any]] = None) -> List[str]:
    """按 uuid 删除,返回**被清理的 auto 指向**列表(``['ma68']``)。

    连带清理 auto 表是调用方(GUI)把 config 传进来的原因:删掉的账号
    还被 auto.<game> 指着 = 下次启动预检必炸,删的时候就该一起清。
    返回清理了哪些键,GUI 拿去提示用户「默认账号已重置」。

    ``config`` 是**已剥离注释的** dict(载入走 load_app_config);本函数
    只改内存结构,写回 config 文件是调用方的事(auto 的落盘走
    config_editor 或 save_app_config,由 GUI 决定)。
    """
    account = find_by_uuid(accounts, uuid)
    if account is None:
        raise AutoLoginError(f"要删除的账号不在账号表中:{uuid!r}")
    accounts.remove(account)
    cleared: List[str] = []
    if config is not None:
        auto = config.get("auto") or {}
        for game_id, target in list(auto.items()):
            if target == uuid:
                auto[game_id] = ""
                cleared.append(game_id)
    return cleared
