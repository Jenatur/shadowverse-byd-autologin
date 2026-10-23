# 协议规范

本文件描述影之诗登录链路上需要复刻的全部协议细节。

**证据等级标注**(全文遵守,请勿混淆):
- ✅ **已验证** — 通过在参考实现上**实际执行代码**得到,可直接采信。
- ⚠️ **已推断** — 由 Python 字节码反汇编推断,结构可信但细节需实测复核。
- ❓ **未知** — 必须靠阶段 0 取证解决。

---

## 1. 参与方与域名

| 域名 | 角色 |
|---|---|
| `service.mkey.163.com` | 网易 SDK 登录服务(扫码登录主流程) |
| `mgbsdk.matrix.netease.com` | 网易 SDK 游戏服务(`uni_sauth` 票据签发) |
| `sdk-os.mpsdk.easebar.com` | 网易 SDK 配置/统计 |
| `who.nie.netease.com` | ⚠️ **网易的"我的公网 IP"服务**。参考实现用它填 SAUTH 里的 `ip` / `aim_info` 字段。**本项目必须去掉这个调用**,见下。 |

### 1.1 ⚠️ 必须去掉的外联:`who.nie.netease.com`

参考实现的 `buildSAUTH()` 会调用 `_get_my_ip()` 去 `who.nie.netease.com` 查你的公网 IP,
实测确认该请求真的会发出去(会触发 urllib3 的 InsecureRequestWarning)。

这与本项目的「零外联」硬约束直接冲突。处理方式(二选一,阶段 1 决定):

1. **配置化**:从本地配置读取一个固定 IP 字符串填入 `ip` / `aim_info`。
2. **局域网地址**:若整个链路都在局域网内,填局域网出口地址。

**无论选哪种,`who.nie.netease.com` 都不允许出现在代码里。**
`tests/test_no_egress.py` 会扫描源码树并断言该域名不存在。

> 副作用提示:`ip` / `aim_info` 是**风控字段**。填一个不合常理的值(比如 `127.0.0.1`)可能触发的风控行为未知。
> 阶段 3 需要实测:用一个固定的真实公网 IP 常量 vs 局域网地址,看服务器是否接受。

---

已知固定解析(参考实现里的硬编码 IP,仅作调试参考,不要写死):
`service.mkey.163.com -> 42.186.193.21`,`sdk-os.mpsdk.easebar.com -> 8.222.80.103`。

---

## 2. 登录流程全景

```
游戏启动
  │
  ├─(1)─ POST service.mkey.163.com/mpay/api/qrcode/create_login?game_id=<GID>&...
  │        ← 响应体含 uuid + qrcode_scanners[0].url(二维码页面地址)
  │        ★ 改写点:把 url 换成自己的本地页面
  │
  ├─(2)─ GET  service.mkey.163.com/mpay/api/qrcode/query?uuid=<UUID>&...
  │        ← 游戏轮询,等待扫码结果。qrcode.status == 2 表示已被扫码确认
  │
  ├─(3)─ GET  service.mkey.163.com/mpay/api/qrcode/scan?uuid=<UUID>&login_channel=...&game_id=<GID>&...
  │        ← 模拟「扫码」动作
  │
  ├─(4)─ POST service.mkey.163.com/mpay/api/qrcode/confirm_login
  │        ← 模拟「确认」动作,body 为表单编码
  │
  ├─(5)─ POST service.mkey.163.com/.../exchange_token
  │        ← 用登录票据换取会话,响应含 user / ext_info
  │
  └─(6)─ POST mgbsdk.matrix.netease.com/<GID>/sdk/uni_sauth    ★ 签名请求
           ← 返回 unisdk_login_json,即游戏真正消费的登录结果
```

第 (6) 步是整个链路的终点,也是唯一需要 `log_key` 签名的地方。

---

## 3. 签名算法 ✅

> 这一节全部经运行时验证,`开发侧金标向量` 里的向量是直接调用参考实现算出来的。

### 3.1 签名原串

```python
def get_sign_src(method: str, url: str, body: str) -> str:
    """method, url, body  →  签名原串"""
    host_part = ""
    stripped = url.replace("://", "")
    i = stripped.find("/")
    if i != -1:
        host_part = stripped[i:]        # ← 从第一个 '/' 到结尾,注意不是 [:i]
    return method.upper() + host_part + body
```

**⚠️ 反直觉的坑**:主机名**不**参与签名。请仔细看下面这组实测边界用例:

| method | url | body | 签名原串 |
|---|---|---|---|
| `POST` | `https://mgbsdk.matrix.netease.com/g37/sdk/uni_sauth` | `D1` | `POST/g37/sdk/uni_sauthD1` |
| `post` | `http://host/path` | `D2` | `POST/pathD2` |
| `GET` | `https://hostonly` | `D3` | `GETD3` |
| `POST` | `https://a.b.c:8443/x/y` | `D4` | `POST/x/yD4` |

注意第 3 行:`url` 没有路径时,**主机名整段被丢掉**,原串直接是 `GET` + body。

### 3.2 签名

```python
sign = hmac.new(key.encode(), src.encode(), hashlib.sha256).hexdigest()
```

输出 64 位小写十六进制。

### 3.3 请求封装 ✅

```python
url    = f"https://mgbsdk.matrix.netease.com/{game_id}/sdk/uni_sauth"
method = "POST"
body   = json.dumps(payload_or_form, cls=CustomEncoder)   # 见下
sign   = calc_sign(url, method, body, log_key)

headers = {
    "X-Client-Sign": sign,
    "Content-Type":  "application/json",
    "User-Agent":    "Dalvik/2.1.0 (Linux; U; Android 12; M2102K1AC Build/V417IR)",
}
r = requests.post(url, data=body, headers=headers, verify=<是否校验SSL>)
return r.json()
```

- `User-Agent` 是**硬编码的固定字符串**,照抄。
- `game_id` 出现在 URL 路径里,用的是**短 ID**。
- `CustomEncoder` 是自定义 JSON 编码器(处理非标准类型);⚠️ 其具体行为未展开,**若 payload 全是基本类型则可忽略**。

---

## 4. `uni_sauth` 请求体(SAUTH 报文)

### 4.1 SAUTH 主体 ✅

`buildSAUTH(login_channel, app_channel, uid, session, game_id, sdk_version, custom_data=None)`:

```python
data = {
    "gameid":              game_id,          # 短 ID
    "login_channel":       login_channel,    # 如 "bilibili_sdk"
    "app_channel":         app_channel,      # 同上
    "platform":            "ad",
    "sdkuid":              uid,              # 渠道账号 uid,字符串
    "udid":                fake_device["udid"],
    "sessionid":           session,          # 渠道账号 access_key
    "sdk_version":         sdk_version,      # 如 "5.9.6"
    "is_unisdk_guest":     0,
    "ip":                  <本机公网/内网 IP>,
    "aim_info":            '{"tz":"+0800","tzid":"Asia/Shanghai","aim":"<ip>","country":"CN"}',
    "source_app_channel":  app_channel,
    "source_platform":     "ad",
    "client_login_sn":     <16 位随机十六进制>,
    "step":                <10 位随机数字>,
    "step2":               <9 位随机数字>,
    "hostid":              0,
    "sdklog":              json.dumps(fake_device),
}
data.update(custom_data or {})
```

- `platform` / `source_platform` 恒为 `"ad"`(安卓)。
- `client_login_sn` / `step` / `step2` 是随机数 → **测试不要断言具体值**,断言格式即可。
- `sdklog` 是字符串化的 JSON,不是嵌套对象。

### 4.2 伪装设备 ✅

来自 `fakeDevice.json`(参考实现里的文件,字段如下):

```json
{"udid": "..."}
```

具体内容在 `C:\ProgramData\idv-login\fakeDevice.json`(206 字节),开发时直接读取本地该文件或自建等价结构。

### 4.3 完整请求体 ✅

> 本节的所有结构都是**实际执行参考实现的 `_build_unisdk_result()` 导出**的,不是读代码猜的。
> 完整样本见 [../开发侧金标向量](../开发侧金标向量) 的 `unisdk_result_sample`。

```python
extra_data = {"realname": json.dumps({"realname_type": 0, "age": 22})}

json_data = {                                        # ← 顺序即最终出现顺序
    "extra_data":       extra_data.get("extra_data"),        # → None(注意是 None,不是 "1")
    "get_access_token": extra_data.get("get_access_token") or "1",   # → "1"
    "sdk_udid":         fake_device["udid"],
    "realname":         extra_data.get("realname"),          # → '{"realname_type": 0, "age": 22}'
}
json_data.update(sauth_body)                         # 4.1 的 18 个字段追加在后面

str_data = dict(json_data)
str_data["username"] = unisdk_json["username"]       # 来自 uni_sauth 响应
str_data = "&".join(f"{k}={v}" for k, v in str_data.items())    # 注意:没有 URL 编码

extra_unisdk_data = {**extra_data,                   # → 只有 realname
                     "SAUTH_STR":  b64(str_data),
                     "SAUTH_JSON": b64(json.dumps(json_data))}
```

最终 POST 的 body(13 个键,**顺序敏感**):

```python
{
    "user_id":           uid,               # "10000001"
    "token":             b64(access_key),   # 单层 base64,不再包 JSON
    "login_channel":     "bilibili_sdk",
    "udid":              fake_device["udid"],
    "app_channel":       "bilibili_sdk",
    "sdk_version":       sdk_version,       # "5.9.6"
    "jf_game_id":        game_id,           # 短 ID,如 "ma68"
    "pay_channel":       "bilibili_sdk",    # ← 不是空串
    "extra_data":        "",                # ← 是空字符串,不是 JSON
    "extra_unisdk_data": <str>,             # ← 是 JSON 字符串,不是嵌套对象
    "gv":   "157",
    "gvn":  "1.5.80",
    "cv":   "a1.5.0",
}
```

> **三个容易写错的点**(都是实测确认的,照抄):
> 1. `extra_unisdk_data` 是**字符串**(内部 JSON 序列化过),不是嵌套对象。
> 2. `extra_data` 是**空字符串** `""`,不是 `json.dumps(extra_data)`。
> 3. `pay_channel` = `"bilibili_sdk"`,不是 `""`。
>
> `SAUTH_STR` 是 `str_data` 的**单层** base64 —— **不是**双层。
> 解码后应得到完整的 `k=v&k=v...` 表单串,见下。

#### SAUTH_STR 解码后的实际内容(实测)

```
extra_data=None
get_access_token=1
sdk_udid=775ae8FEF020e038
realname={"realname_type": 0, "age": 22}
gameid=ma68
login_channel=bilibili_sdk
app_channel=bilibili_sdk
platform=ad
sdkuid=10000001
udid=775ae8FEF020e038
sessionid=<access_key>
sdk_version=5.9.6
is_unisdk_guest=0
ip=<公网IP>
aim_info={"tz":"+0800","tzid":"Asia/Shanghai","aim":"<公网IP>","country":"CN"}
source_app_channel=bilibili_sdk
source_platform=ad
client_login_sn=<16位hex>
step=<10位数字>
step2=<9位数字>
hostid=0
sdklog=<device json>
username=<uid 对应的昵称>
```

字段顺序 = `json_data` 的插入顺序,不能用 `sort_keys`。

---

## 5. B站渠道凭据

### 5.1 默认参数 ✅

当云端配置里查不到该游戏的 `bilibili_sdk` 配置时,参考实现会回退到硬编码默认值:

```python
bili_game_id = "183"
bili_app_key = "h9Ejat5tFh81cq8"     # B站开放平台 app_key
bili_sdk_ver = "5.9.6"
```

### 5.2 账号记录 ✅

存储在 `channels.json`,数组结构:

```json
[{
  "uuid": "bili-bilibili_sdk-100001",
  "name": "示例昵称",
  "login_channel": "bilibili_sdk",
  "channel_name": "bilibili_sdk",
  "login_info": {
    "code": "100001",
    "src_client_type": 1,
    "login_channel": "bilibili_sdk",
    "src_client_country_code": "CN"
  },
  "loginResp": { "uid": 10000001, "access_key": "…32位hex…" },
  "game_id": "aecflsysdmaaaag3-g-g37",
  "bili_sdk_ver": "5.9.6"
}]
```

账号 `uuid` 的命名规则:`{渠道}-{login_channel}-{code}`。

完整数据模型见 [../spec/account.schema.json](../spec/account.schema.json)。

---

## 6. 改写规则(拦截层)

### 6.1 `create_login` 响应改写 ✅

```python
body = json.loads(response.content)
body["qrcode_scanners"][0]["url"] = (
    f"{本地页面基址}/_idv-login/index?game_id={effective_game_id}&view=accounts"
)
body["scanner_guide_text"] = "…引导文案…"
body["scanner_download_guide_text"] = "…"
response.content = json.dumps(body).encode()
```

**要求**:除上述字段外逐字节保持不变。测试做 round-trip 对比。

参考实现的本地页面基址是 `https://localhost`(兼容模式),非兼容模式用 `idvlogin://open?game_id=…&view=accounts`。本项目用前者。

### 6.2 `qrcode/query` 观察 ✅

```python
data = json.loads(response.content)
if data.get("code", -1) != -1:
    log.error("扫码登录失败，错误码：%s，信息：%s", data.get("code"), data.get("reason"))
    # 这里的 code 是网易的业务错误码,失败时打日志即可
qr_status = data.get("qrcode", {}).get("status", 0)
if qr_status == 2:                      # 2 = 已被扫码/确认
    push_pending_login_info(game_id, process_id, data["login_info"])
```

**不改写响应**,只做观察。

### 6.3 状态标志生命周期 ✅

参考实现用一个全局标志 `CHANNEL_ACCOUNT_SELECTED` 来区分「自动登录中」和「手工扫码」两种模式,多处读写:

| 动作 | 位置 |
|---|---|
| 置为账号 uuid | `create_login` 命中自动登录配置时;用户手动切换渠道时 |
| 置为 `''` | 程序启动时;`simulate_scan` 非 200 时;`simulate_scan` 抛异常时;`confirm` 无数据时;**`confirm` 返回非 200 时** |
| **未清除** | ⚠️ **`confirm` 返回 200 的成功路径没有清除**(代码在 `return` 之后)**—— 这是参考实现的 bug** |

**后果**:自动登录一旦触发(成功或失败),同一次会话里后续的手工扫码保存会被静默拦掉,直到重启程序。

**本项目要求**:无论成功失败,状态标志都必须可靠清理。这条会被 `tests/test_failure_modes.py` 覆盖。

---

## 7. 金标测试向量

见 [../开发侧金标向量](../开发侧金标向量)。
由参考实现**实际执行**导出,`tests/test_signature.py` 直接断言。

---

## 8. ❓ 仍未知、必须实测的部分

| # | 未知项 | 怎么解 |
|---|---|---|
| 1 | 影之诗的 `game_id` | 抓 `create_login` 请求 |
| 2 | 影之诗的 `log_key` | 见 阶段 0 取证(已解决;记录在开发侧) |
| 3 | `SAUTH_STR` 双层 base64 的确切嵌套 | 逐字段比对真实抓包 |
| 4 | 服务器对 `uni_sauth` 的成功/失败返回码语义 | 抓一次成功 + 几次失败 |
| 5 | `create_login` 的完整查询参数集 | 抓包 |
| 6 | 影之诗 SDK 是否有证书 pinning | 阶段 2 实测 |
