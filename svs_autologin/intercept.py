"""拦截规则与「账号已选中」状态机。

三个入口与参考实现的对应(PLAN.md 阶段 1 说明):

* ``on_create_login``   = ``_modify_create_login_response``
* ``on_qrcode_query``   = ``_handle_qrcode_query_response``
* ``on_exchange_token`` = ``_handle_exchange_token_response``

外加把参考实现里散落的清理逻辑收敛成的显式入口:
``finish_auto_login`` / ``_run_guarded`` / ``_save_records`` / ``_schedule_scan``。

状态机一句话(tests/test_intercept_rules.py 模块 docstring):
看到 create_login 且该游戏配置了自动登录 → 置 selected 标志、安排延迟扫码;
标志置位期间 qrcode/query 处理器提前返回、exchange 处理器跳过扫码记录;
**流程结束时无论成功、失败还是异常,标志必须被清掉。**

参考实现的缺陷 2(docs/protocol.md §6.3)在这里修掉:它在 HTTP 200 的
成功路径上 ``return``,清理代码在 return 之后够不到,导致同一次会话里
后续的手工扫码保存被静默拦掉。本实现的 ``finish_auto_login`` 把
「清标志」放在**一切副作用之前**——保存失败、回调抛异常,标志都已经清了。
"""

from __future__ import annotations

import functools
import logging
import threading
from typing import Any, Callable, Dict, List, Mapping, Optional

from svs_autologin.accounts import Account, build_account, find_by_uuid, save_accounts, upsert
from svs_autologin.errors import AutoLoginError
from svs_autologin.game_id import get_short_game_id
from svs_autologin.qrcode_login import DEFAULT_BASE_URL, now, simulate_scan

log = logging.getLogger(__name__)

# 参考实现的本地页面基址(兼容模式,docs/protocol.md §6.1)。
LOCAL_PAGE_BASE = "https://localhost/_idv-login/index"

DEFAULT_LOGIN_DELAY = 3  # 秒,参考实现实测值

DEFAULT_CONFIRM = {"clear_flag_on_success": True, "cleanup_timeout": 5}
DEFAULT_TOGGLES = {"scan_record_enabled": True, "auto_close": True}


def _normalize_config(config: Mapping[str, Any]) -> Dict[str, Any]:
    """补齐可选节的缺省值,返回浅拷贝(不修改调用方的 dict)。

    两个目的:调用方(测试/上层)可以只给最小配置;规则内部读取
    ``config["confirm"]`` 等节时不必层层 ``.get``。
    """
    merged: Dict[str, Any] = dict(config)
    for section, defaults in (("confirm", DEFAULT_CONFIRM), ("toggles", DEFAULT_TOGGLES)):
        existing = merged.get(section)
        merged[section] = {**defaults, **(existing if isinstance(existing, Mapping) else {})}
    merged.setdefault("auto", {})
    merged.setdefault("games", {})
    merged.setdefault("qrcode", {})
    return merged


class State:
    """一次会话的全部可变状态。约定所有字段公开可读,由 InterceptRules 写。"""

    def __init__(self) -> None:
        self.selected: Optional[str] = None          # CHANNEL_ACCOUNT_SELECTED
        self.pending_login_info: Optional[Dict[str, Any]] = None
        # 手工扫码路径上暂存的 exchange_token 响应体:落盘时和 pending_login_info
        # 一起派生出账号记录(阶段 3,accounts.build_account)。
        self.pending_exchange: Optional[Dict[str, Any]] = None
        self.last_response_rewritten: bool = False
        self.recorded: bool = False
        # 内部:qrcode 缓存 {(short_game_id, process_id): body_uuid}
        self.qr_cache: Dict[tuple, str] = {}
        # 内部:已排起的延迟扫码定时器(便于测试/退出时取消)
        self.timers: List[threading.Timer] = []

    def cancel_timers(self) -> None:
        for t in self.timers:
            t.cancel()
        self.timers.clear()


class InterceptRules:
    """纯逻辑改写规则。不碰网络;真实 HTTP 由阶段 2 的 addon 驱动本类。"""

    def __init__(
        self,
        config: Mapping[str, Any],
        accounts: Optional[List[Account]] = None,
        state: Optional[State] = None,
        *,
        transport: Optional[Callable[..., Any]] = None,
        accounts_path: Optional[str] = None,
    ) -> None:
        # 归一化:confirm / toggles 等可选节补上缺省,内部读取不再层层兜底。
        self.config: Dict[str, Any] = _normalize_config(config)
        self.accounts: List[Account] = list(accounts or [])
        self.state = state if state is not None else State()
        # 阶段 3 的两个注入点。transport 为零外联的唯一出口(docs/constraints.md
        # C1):扫码/确认这两个请求必须由中转层代发,规则层只管编排。
        self.transport = transport
        # 账号表落盘位置;None = 只在内存里(测试默认)。
        self.accounts_path = accounts_path

    # ------------------------------------------------------------------
    # create_login
    # ------------------------------------------------------------------

    def on_create_login(
        self,
        query: Mapping[str, Any],
        body: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """改写 create_login 响应:只动 ``qrcode_scanners[0].url``,其余逐字节不变。

        * 返回**新 dict**,不改调用方的 payload(round-trip 契约);
        * 无条件清一次 selected 标志(新一轮登录从这里开始);
        * ``auto`` 表(按短 ID 索引)有非空项 → 置标志并**安排**(不内联执行)延迟扫码;
        * effective id 的取值顺序:dst_jf_game_id > hosted_target_game_id > game_id。
        """
        raw = (
            query.get("dst_jf_game_id")
            or query.get("hosted_target_game_id")
            or query.get("game_id")
            or ""
        )
        effective = get_short_game_id(raw)
        process_id = query.get("process_id", "")

        # 每轮登录开始:无条件清标志(参考实现同样在此重置)。
        self.state.selected = None

        uuid = body.get("uuid", "")
        if effective and process_id is not None:
            self.state.qr_cache[(effective, process_id)] = uuid

        # ---- 改写(浅拷贝 payload 与 scanner[0],不污染调用方) ----
        out: Dict[str, Any] = dict(body)
        scanners = body.get("qrcode_scanners") or []
        if scanners:
            copies = [dict(s) for s in scanners]
            copies[0]["url"] = self._local_page_url(effective)
            out["qrcode_scanners"] = copies

        # ---- 自动登录判定 ----
        auto_uuid = (self.config.get("auto") or {}).get(effective, "")
        if auto_uuid:
            self.state.selected = auto_uuid
            delay = self._login_delay(effective)
            log.info(
                "create_login 拦截:game_id=%s(短 %s)→ 自动登录 %s,%s 秒后模拟扫码",
                raw, effective, auto_uuid, delay,
            )
            self._schedule_scan(
                delay,
                functools.partial(
                    self._auto_login_flow,
                    raw_game_id=raw,
                    effective_game_id=effective,
                    qr_uuid=uuid,
                    account_uuid=auto_uuid,
                ),
            )
        else:
            log.info("create_login 拦截:game_id=%s(短 %s),未配置自动登录", raw, effective)
        return out

    # ------------------------------------------------------------------
    # qrcode/query —— 只观察,不改写
    # ------------------------------------------------------------------

    def on_qrcode_query(
        self,
        query: Mapping[str, Any],
        body: Mapping[str, Any],
    ) -> None:
        """观察扫码进度。**不改写响应。**

        * selected 标志置位期间:立即返回,不做任何记录(自动登录由我们驱动,
          两边不能抢;一个滞留的标志会把这段提前返回变成永久,这正是缺陷 2
          的可观测症状);
        * ``code != -1``:业务失败,记日志并丢弃缓存的 qrcode 条目;
        * ``qrcode.status == 2``(已扫码确认):暂存 ``login_info`` 供
          exchange 阶段落盘。
        """
        if self.state.selected:
            return None

        code = body.get("code", -1)
        if code != -1:
            log.error("扫码登录失败，错误码：%s，信息：%s", code, body.get("reason"))
            effective = get_short_game_id(query.get("game_id", "") or "")
            self.state.qr_cache.pop((effective, query.get("process_id", "")), None)
            return None

        qr = body.get("qrcode") or {}
        if qr.get("status", 0) == 2:
            login_info = body.get("login_info")
            if login_info is not None:
                self.state.pending_login_info = dict(login_info)
                log.info("qrcode/query:status=2,暂存 login_info 待落盘")
        return None

    # ------------------------------------------------------------------
    # exchange_token
    # ------------------------------------------------------------------

    def on_exchange_token(
        self,
        query: Mapping[str, Any],
        body: Mapping[str, Any],
        status: int = 200,
    ) -> Mapping[str, Any]:
        """exchange_token 观察/收尾。

        自动模式(selected 置位):**不改写**响应,直接收尾自动登录
        (finish_auto_login 内部保证清标志,成功失败都清)。
        手工模式:响应标记为已改写(字节级改写由阶段 2 的 addon 完成,
        本层维护规则状态),并在 status==200 且开了扫码记录时把暂存的
        pending login_info 落盘。
        """
        was_selected = self.state.selected is not None

        if was_selected:
            ok = (status == 200)
            log.info("exchange_token:自动登录路径,ok=%s,不改写响应", ok)
            self.state.last_response_rewritten = False
            self.finish_auto_login(ok=ok)
            return body

        self.state.last_response_rewritten = True
        if status == 200 and self._scan_record_enabled() and self.state.pending_login_info:
            # 阶段 3:响应体本身就是账号记录的素材(PC 形态的 user/ext_info,
            # 见 开发侧取证记录)。暂存给 _save_records 派生。
            self.state.pending_exchange = dict(body)
            self.state.recorded = True
            self._save_records()  # 消费 pending_login_info + pending_exchange
            log.info("exchange_token:手工扫码记录已保存")
        return body

    # ------------------------------------------------------------------
    # 收尾:缺陷 2 的修复所在
    # ------------------------------------------------------------------

    def finish_auto_login(
        self,
        ok: bool = False,
        error: Optional[BaseException] = None,
        on_complete: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> Dict[str, Any]:
        """自动登录收尾。**先清状态,再做任何副作用。**

        顺序是契约(tests/test_failure_modes.py TestCallbackOrdering /
        test_flag_cleared_even_if_saving_the_record_fails):

        1. 清 selected(以及 pending)—— 之后无论保存抛 OSError、
           回调抛 ValueError、还是根本没人调用回调(cleanup_timeout 兜底),
           标志都不可能滞留;
        2. 失败有 error 时记日志;
        3. ok 时调用 ``_save_records()``(可覆写;它抛的异常照常向上传播,
           但状态已清);
        4. 调用 ``on_complete(result)``(若提供;回调看到的必然是干净状态,
           回调抛出的异常也照常向上传播)。

        ``confirm.cleanup_timeout``(schema 缺省 5 秒)在参考实现里约束
        「回调最迟多久之后标志必须被清」;由于本实现把清标志放在回调
        **之前**,这个不变式天然成立,超时值不再参与控制流。若使用者把
        ``confirm.clear_flag_on_success`` 关掉(schema:必须保持 true),
        记一条警告——缺陷 2 就是这么回来的。
        """
        if not self.config["confirm"].get("clear_flag_on_success", True):
            log.warning("confirm.clear_flag_on_success 已被关闭:这会重新引入参考实现的缺陷 2")
        self.state.selected = None
        self.state.pending_login_info = None
        self.state.pending_exchange = None

        if error is not None:
            log.warning("自动登录失败:%r", error)

        if ok:
            self._save_records()

        result = {"ok": ok, "error": error}
        if on_complete is not None:
            on_complete(result)  # 回调看到的 selected 已经是 None
        return result

    def _run_guarded(self, fn: Callable[[], Any]) -> Any:
        """执行 fn;抛任何 Exception 都先走 finish_auto_login 清状态再重抛。

        参考实现里延迟扫码线程的异常路径正是标志泄漏的来源之一。
        """
        try:
            return fn()
        except Exception as exc:
            self.finish_auto_login(ok=False, error=exc)
            raise

    # ------------------------------------------------------------------
    # 可覆写的扩展点(测试会 monkeypatch 这几个名字)
    # ------------------------------------------------------------------

    def _schedule_scan(self, delay: float, fn: Callable[[], Any]) -> Any:
        """延迟 delay 秒后在**独立线程**执行 fn(不阻塞响应)。

        默认用 threading.Timer(daemon);fn 的异常由 _run_guarded 兜住:
        状态被清、错误被记录,不让工作线程把栈打到 stderr。
        """
        timer = threading.Timer(float(delay), lambda: self._quiet(self._run_guarded, fn))
        timer.daemon = True
        self.state.timers.append(timer)
        timer.start()
        return timer

    def _auto_login_flow(
        self,
        raw_game_id: str,
        effective_game_id: str,
        qr_uuid: str,
        account_uuid: str,
    ) -> None:
        """延迟到期后的「模拟扫码 → 模拟确认」流程(阶段 3)。

        时序契约(与游戏自己的轮询对齐,见 开发侧取证记录 的登录链):

        1. 我们 POST ``confirm_login``,mkey 侧这个二维码会话变成已授权;
        2. 游戏的 ``qrcode/query`` 下一次轮询(约 10s)看到 ``status: 2``;
        3. 游戏自己去 POST ``exchange_token``,拿到内嵌 SAUTH 的响应;
        4. 响应回到 ``on_exchange_token``,那里才 ``finish_auto_login(ok=True)``。

        所以本方法**成功时不清 selected 标志** —— 标志要活到第 3 步。失败时抛异常,
        由 ``_run_guarded`` 清标志并记日志,不会留下卡死的状态
        (参考实现这条路径是 ``return False`` + 手动清全局变量,失败原因散在日志里)。

        ``raw_game_id`` 用的是 create_login query 里那个**完整** id:
        mkey 会在 ``scan`` 回 1424 时把正确的 id 塞在 ``resp['game']['id']`` 里,
        ``qrcode_login.simulate_scan`` 负责那次重试。
        """
        account = find_by_uuid(self.accounts, account_uuid)
        if account is None:
            raise AutoLoginError(
                f"auto.{effective_game_id} 指向的账号 {account_uuid!r} 不在账号表中"
                f"(账号文件:{self.accounts_path or '未配置,内存态'})"
            )
        if self.transport is None:
            raise AutoLoginError(
                "没有可用的中转 transport:扫码/确认这两个请求必须由中转层代发"
                "(docs/constraints.md C1),构造 InterceptRules 时传 transport="
            )

        settings = self._qrcode_settings()
        result = simulate_scan(
            account=account,
            qr_uuid=qr_uuid,
            game_id=raw_game_id,
            transport=self.transport,
            base_url=settings["base_url"],
            verify=settings["verify"],
            timeout=settings["timeout"],
        )

        # mkey 已接受确认 —— 这是我们能观测到的最强信号,刷新时间戳并落盘。
        account.last_login_time = now()
        self._persist()

        log.info(
            "模拟扫码/确认成功:账号=%s game_id=%s(短 %s),等游戏换票据;响应=%r",
            account.uuid, raw_game_id, effective_game_id, result,
        )

    def _save_records(self) -> None:
        """把暂存的扫码结果并进账号表(数据落盘优先于可观测性)。

        两条路径:

        * **PC 形态**(``exchange_token`` 响应里有 ``user`` 对象)→ 用
          ``accounts.build_account`` 派生完整记录并 upsert,按
          ``user_info['id']`` 去重后落盘;
        * **旧形态**(响应里没有 ``user``,阶段 1 的 fixture 就是这种)→
          原样把 ``login_info`` 追加进内存表,不猜、不造字段。
          ``tests/test_intercept_rules.py::TestExchangeToken`` 咬的就是这条。

        ``self.accounts_path`` 为 None 时不落盘(测试默认)。
        """
        info = self.state.pending_login_info
        if info is None:
            return

        exchange = self.state.pending_exchange or {}
        if exchange.get("user"):
            account = upsert(self.accounts, build_account(info, exchange))
            self.state.pending_login_info = None
            self.state.pending_exchange = None
            self._persist()
            log.info("已保存账号记录:%s(共 %s 条)", account.uuid, len(self.accounts))
            return

        self.accounts.append(dict(info))
        self.state.pending_login_info = None
        self.state.pending_exchange = None
        log.debug("已暂存扫码记录(响应里无 user 对象,未派生完整账号),%s 条", len(self.accounts))

    def _persist(self) -> None:
        """账号表落盘。未配置路径时是空操作。

        写盘失败**不**吞掉:账号文件的写入失败对使用者是可行动的(磁盘满、权限),
        而且此刻状态已经清干净了 —— ``finish_auto_login`` 把清标志放在副作用之前
        就是为了这个(开发侧架构拆解 缺陷 2)。
        """
        if not self.accounts_path:
            return
        save_accounts(self.accounts, self.accounts_path)

    def _qrcode_settings(self) -> Dict[str, Any]:
        """``config["qrcode"]`` 的三个可调项,缺省见 spec/app-config.schema.json。"""
        qr = self.config.get("qrcode") or {}
        return {
            "base_url": qr.get("base_url") or DEFAULT_BASE_URL,
            "verify": qr.get("verify", True),
            "timeout": float(qr.get("timeout", 10)),
        }

    # ------------------------------------------------------------------
    # 预检(阶段 4):开工前发现配置问题,好过登录窗前发现
    # ------------------------------------------------------------------

    def preflight(self) -> List[str]:
        """检查 ``auto`` 表指向的账号都可用,返回人类可读的问题清单(空=健康)。

        只查本地状态,不拨号 —— 这是启动期的检查,网络问题留给登录时的
        错误路径。每条问题都是完整一句话,可直接进弹窗/日志。
        """
        problems: List[str] = []
        auto = self.config.get("auto") or {}
        for game_id, account_uuid in sorted(auto.items()):
            if not account_uuid:
                continue
            account = find_by_uuid(self.accounts, account_uuid)
            if account is None:
                problems.append(
                    f"auto.{game_id} 指向的账号 {account_uuid!r} 不在账号表中"
                    f"(账号文件:{self.accounts_path or '未配置'});"
                    f"请先手工扫码一次,再把新记录的 uuid 填进 auto.{game_id}"
                )
                continue
            user = account.user_info
            if not user.get("id") or not user.get("token"):
                problems.append(
                    f"账号 {account_uuid!r}(auto.{game_id})缺少 id/token,"
                    f"凭据不完整,需要重新扫码授权"
                )
        return problems

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------

    @staticmethod
    def _quiet(fn: Callable[..., Any], *args: Any) -> None:
        try:
            fn(*args)
        except Exception:
            log.warning("延迟扫码线程异常", exc_info=True)

    def _local_page_url(self, effective_game_id: str) -> str:
        return f"{LOCAL_PAGE_BASE}?game_id={effective_game_id}&view=accounts"

    def _login_delay(self, effective_game_id: str) -> float:
        game_cfg = (self.config.get("games") or {}).get(effective_game_id) or {}
        return float(game_cfg.get("login_delay", DEFAULT_LOGIN_DELAY))

    def _scan_record_enabled(self) -> bool:
        return bool((self.config.get("toggles") or {}).get("scan_record_enabled", True))
