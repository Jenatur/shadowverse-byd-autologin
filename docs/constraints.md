# 硬约束

本文件是**验收标准**的一部分。任何一条不满足,该版本不予验收。

---

## C1 — 零外联

**定义**:运行期间,本工具**不得**发起任何目标是公网的主机连接。

唯一的网络行为必须是:

1. 监听本机 / 局域网地址,等待游戏(或模拟器)连进来;
2. 把游戏发来的请求**转发**给网易的服务器。

也就是说:**本工具自己不发请求**,只做被动中转。所有出站流量都是游戏的,不是工具的。

> **唯一例外(2026-10-12 拍板,方案 A)**:自动登录要顶替手机的位置,由工具
> 自己发 `qrcode/scan` + `qrcode/confirm_login` 两个请求 —— 游戏自己的
> `exchange_token` 请求体里没有 uuid(`phase2b_flows/0046`),凭据只能在
> confirm 那一步由扫码方喂进去,不自己发就无法替手机。此例外的全部边界:
>
> * 出站代码只存在于 `tools/relay_transport.py` **一个文件**;
>   `tests/test_no_egress.py` 的 `OUTBOUND_ALLOWLIST` 显式豁免且仅豁免它
>   (与 g37 log_key 白名单同一套纪律),另有一条测试钉死 `import requests`
>   不出现在任何其他交付源文件里。
> * 目标只允许 `https://service.mkey.163.com`(下方白名单成员);
>   `relay_transport` 拒绝非 https 目标,`config.py` 校验 `qrcode.base_url`。
> * 出站路径与游戏流量同一条路:hosts 重定向 → 本地 443 反代 → 真实 mkey,
>   同一套 mitmdump 审计日志,不另开直连通道。
> * 拨号前校验目标解析到回环地址,并且 Session 显式 `trust_env=False` ——
>   不读环境变量代理、也不读 Windows 注册表里的系统代理。2026-10-20 的
>   自动登录失败正是系统代理把请求带离了这条路
>   (见 开发侧修复记录)。
> * 自检探针 `relay_transport.probe_chain()` 只对 `127.0.0.1:443` 做一次
>   TLS 握手(验证反代出示的证书),不发 HTTP、不连任何公网主机;它是这条
>   例外的配套,不新增出站能力。

### 为什么要定这条

参考实现不满足这一点。实测证据:

| 行为 | 证据 |
|---|---|
| 启动时拉云端配置 | 依次尝试 `gitee.com`(HTTP 451)、`hk.gh-proxy.org`、`cdn.jsdelivr.net` |
| 签名时查公网 IP | `who.nie.netease.com`,返回真实公网 IP `` |
| 下载并执行远程 Python | `hotfix_src\mitm_addon_<hash>.py`,进程内 `exec` |
| 崩溃上报 | 见 `src\main.py` 异常处理路径 |

后果:作者(或任何控制那些域名的人)**随时知道你在跑、你的 IP、以及可以在你机器上执行任意代码**。

### 怎么保证

| 措施 | 位置 |
|---|---|
| 没有出站 HTTP 客户端 | 代码里不出现 `requests`/`urllib`/`httpx` 的**主动调用** |
| 主机白名单 | 见下表,只允许转发到这些 host |
| 自动化检查 | `tests/test_no_egress.py` |
| 运行期兜底 | mitmproxy addon 里,目标不在白名单一律 502,不尝试连接 |

**允许转发到的 host(仅此列表)**:

```
mgbsdk.matrix.netease.com
service.mkey.163.com
sdk-os.mpsdk.easebar.com
*.matrix.netease.com
*.mkey.163.com
*.easebar.com
```

**禁止出现在源码里的字符串**(`test_no_egress.py` 会扫):

```
who.nie.netease.com
gitee.com
gh-proxy
jsdelivr
cdn.
raw.githubusercontent
```

**阶段 5 补充(2026-10-13):构建期下载**。`tools/build_runtime.ps1` 在
构建分发运行时时会从 `python.org` / `bootstrap.pypa.io` / `pypi.org`
下载(python embed zip、get-pip、钉版 wheel)。这是**构建期一次性**
行为,产出 `dist/` 树;交付产物(`dist/svs-autologin/<ver>/`)运行期
零外联 —— C1 管的是运行期,构建机不是用户机,不在此约束内。出站禁式
扫描对 `tools/` 全部 `.py/.ps1/.bat/.json` 生效,`build_runtime.ps1`
里的下载 URL 不在禁词表内(它们不是运行期行为)。

---

## C2 — 只监听本机或局域网

**定义**:所有 listener 的绑定地址必须在下列集合内。

```
127.0.0.1
::1
0.0.0.0        # 仅在「给模拟器用」时允许,且必须确认宿主机防火墙只放行局域网段
192.168.x.x
10.x.x.x
172.16.x.x ~ 172.31.x.x
```

**禁止**:绑定公网 IP、UPnP 端口映射、frp / ngrok / cloudflared 之类内网穿透。

`tests/test_no_egress.py` 同时扫描监听地址字面量。

### 关于 0.0.0.0 的取舍

MuMu 有两种网络模式:

| 模式 | 模拟器看到的宿主机地址 |
|---|---|
| NAT(默认) | `10.0.2.2`(QEMU 网关) |
| 桥接 | 宿主机真实局域网 IP |

- **NAT 模式优先**。监听 `127.0.0.1` 不一定够 —— QEMU 的 10.0.2.2 会 NAT 到宿主机的 `127.0.0.1`?
  **不一定**,取决于 MuMu 的实现。**必须实测**。
- 若 NAT 走不通,退到「监听宿主机的局域网 IP」,并通过 Windows 防火墙限定**仅本地子网**可访问。
- **不要**用 `0.0.0.0` 图省事。

---

## C3 — 完全可回滚

工具退出(正常或异常)后,系统状态必须和启动前**完全一致**。

### 必须回滚的东西

| 项目 | 回滚动作 | 参考实现的日志 |
|---|---|---|
| NRPT DNS 策略 | 删除本次添加的规则 | `已清理 NRPT 策略` |
| 本地 DNS 服务 | 停止监听 53 | `DNS 服务已停止` |
| 代理监听 | 关闭端口 | `代理服务已停止` |
| 自定义 URI scheme | 注销注册表项 | `已注销 URI scheme` |
| 代理设置(若改过) | 恢复原值 | `代理设置已恢复` |
| 临时文件 | 删除 | `hotfix_src\` 会被清空 |
| CA 证书 | **不自动删**(见下) | — |

### 关于 CA 证书 —— 这条必须由人来做

参考实现会把它的根证书装进系统信任区,**卸载时不删**。这意味着卸载后,
那张 CA 私钥还在磁盘上,任何拿到它的人都能冒充**任意** HTTPS 站点。

**本项目要求**:

1. 证书私钥文件权限收紧(仅当前用户可读)。
2. 安装/卸载脚本各一份,`tools/install.ps1` / `tools/uninstall.ps1`(阶段 5
   落地;早先规划的 `install-ca.md`/`uninstall-ca.md` 文档形式已被实际
   脚本取代),**显式告知**用户这一步做了什么。
3. 程序退出时打印一行醒目提示:**CA 仍在信任区,如需移除请运行 uninstall 脚本**。
4. 优先方案:只把 CA 装进 **MuMu 模拟器内部** 的信任区,不动宿主机。
   这样影响面严格限制在模拟器里,宿主机完全干净。

**阶段 5 实况记录(2026-10-13)**:

* PC 高清版链路(阶段 2 起)CA 必须装宿主机 `LocalMachine\Root` —— 游戏
  是宿主进程,不存在「只装模拟器」的选项;上面的优先方案只适用已被放弃
  的模拟器路线。
* **certs ACL 分层(2026-10-14 审查修正)**:数据目录整体
  `Users=Modify`(config/accounts/log 运行期要写),但 `certs\` 子目录
  **断继承单独收紧**:SYSTEM/Administrators/安装用户 Full,其余 Users
  只读。理由:这张 CA 被 `LocalMachine\Root` 信任 —— 私钥可写 = 任何
  本地用户能换一张全机信任的 MITM CA,这是真实威胁,不是过度防御;
  而「运行期非提权签叶子证书」只需要**读+执行**(代理以安装用户身份
  跑),Modify 是审查发现的历史偏差,已收回。多用户机器上第二个账户
  仍可运行工具(读 CA 足够),只是不能换 CA —— 恰是想要的边界。
* 卸载器**人触发**删除 Root 里的 mitmproxy CA —— 满足本节「不自动删、
  由人来做」的要求:uninstall.ps1 只在用户显式运行它时才动手。删除
  精度:数据目录还在时按**证书文件指纹**(thumbprint)精确移除本安装
  的那张;数据目录已删(无从取指纹)才退回按 Subject 匹配,逐张打印
  让操作者看清删了什么。

### 回滚的实现方式

用 `try/finally` + 一个显式的「已做的事」栈:

```python
applied = []          # 每做一步 append 一个回滚闭包
try:
    ...
finally:
    for undo in reversed(applied):
        try: undo()
        except Exception: log.exception('回滚失败')   # 单个失败不能阻断其余回滚
```

⚠️ 参考实现在 `handle_exit` 里是**顺序硬编码**的清理,任一步抛异常后面就不执行了。
本项目必须改成上面的模式。

---

## C4 — 仓库里不放明文凭据

`.gitignore` 必须包含:

```
config.local.json
accounts.json
*.log
certs/
cache/
```

`config.local.json`(含 `log_key`、账号 `access_key`)不进版本库,只在本机存在。
仓库里只放 `config.example.json`,值全部留空/占位。

`tests/` 里的 fixture 一律用**假数据**(见 `tests/fixtures/`,uid/token 全是编造的)。

---

## C5 — 上游参考实现只读

本项目**不修改** `上游参考实现安装目录\` 下的任何文件。

理由:
- 那边的 `config.json` 是**运行状态**,程序退出时会用内存里的副本**整个覆写**,
  手工改会被冲掉(实测:改完的键在下次退出后仍在,但并发修改必然丢失)。
- 需要看它的代码,只读 `.pyc`,(反汇编方法存档于开发侧)。

若确实需要改它的配置,**必须先把程序完全关闭**。

---

## C6 — 风险边界(必须让使用者知情)

本工具做的事情,技术上是:

> 在用户自己的机器上,拦截用户自己的游戏客户端与厂商服务器之间的 HTTPS 流量,
> 并用预存的凭据替用户完成一次 SDK 登录握手。

必须同时说明:

1. **流量解密**。要 MITM 就必须往信任区装一张根证书,该证书能解开**机器上任何** HTTPS,
   不止游戏。这是本方案最大的一处信任付出。
2. **违反用户协议**。自动化登录 + 伪造 SDK 侧字段属于典型的自动化外挂行为,
   账号存在封禁风险。这不是技术问题,是使用者要自己承担的后果。
3. **凭据存盘**。`access_key` 会明文存在本地 JSON 里(参考实现就是这样)。
   任何能读到那个文件的程序都能冒用该账号。
4. **参考实现的远程代码执行能力**。本项目**已经移除**,但如果你还在跑原版 IDV-Login,
   请注意作者可以在你机器上执行任意代码。

**建议的知情同意做法**:首次运行时弹一次说明,明确写出上面 4 条,让使用者确认后才继续。

**阶段 5 已实现(2026-10-13)**:GUI 首跑弹 `ConsentDialog`
(`tools/gui_app.py`),四条全文与上面对应;拒绝 = 程序退出;同意落
`<data>\consent.json`(`svs_autologin/consent.py`,版本 + 时间戳),
之后不再打扰。

---

## 验收清单

发布前逐条打勾:

- [ ] 抓包确认运行期没有任何非网易域名的出站连接
- [ ] listener 绑定地址全部落在 C2 允许集合内
- [ ] 正常退出 / Ctrl-C / 强杀 三种情况下,NRPT、DNS、代理端口都已回滚
- [ ] 退出时打印了 CA 提示
- [ ] `git ls-files` 里没有 `config.local.json` / `*.log` / 证书私钥
- [x] `tests/` 全绿(2026-10-13:embed 331 passed + 1 skipped;出货
      runtime 335 passed —— gui_shell 四例在 runtime 侧真跑)
- [ ] `上游参考实现安装目录\` 的 mtime 没有变化(除它自己运行导致的外)
- [x] 首次运行有知情同意弹窗(2026-10-13,`ConsentDialog`;真机验收
      门 T6 复核「只弹一次」)
