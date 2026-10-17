# 微信小程序收集（指定才开）

> **只收集。** 测、定级、报告全部走本包 SKILL（`dig-scope` §4 + `vuln-report-format`）。  
> 不要用 MCP 出 OWASP 稿；不要在通道里改参打穿。降级解包只按本篇。

## 何时开 / 何时不开

| 开 | 不开 |
|----|------|
| 用户**点名了**具体小程序名或 appId，并要挖这个客户端 | 只挖集团 / 只挖 Web，没点名客户端 |
| 用户另说「带出也跟」之后，才跟 Web/JS 里抄到的 appId | Web/JS 带出 appId、小程序网关 → **记下不跟** |
| — | 微信搜品牌当种子；把集团名当小程序任务 |

点名必须是具体客户端，不是集团名。

## 两段不要混

| 段 | 做 | 不做 |
|----|----|------|
| **收集**（本篇） | 路由/接口/参数、token 位置、sign/enc、host、硬编码钥、演示号 | 不打 IDOR/注入；通道里不改参当主路径 |
| **测试**（本包 SKILL） | 收集物当清单+钥匙，走 `dig-scope` §4 | 不把「再 hook 一轮」当进站准入 |

导航出流量 = 收集。换 id、omit 票、四件套 = curl / Yakit，不在 MCP 里打穿。

## 环境前置检测（开场一次）

点名小程序且说「动」之后，**先只读检查，再收集**。本轮只做这一次。`00-doctor` 属于使用前安装，不在本任务里催。

本机 WMP 常见两端口（对不上先问，不要盲换）：

| 查 | 过 | 问题 |
|----|----|------|
| MCP（常见 `http://127.0.0.1:49999`）能握手 | 通 | 没起 MCP |
| WMPF/CDP（常见 `ws://127.0.0.1:62000`）在听 | 通 | 通常要先打开点名的那个小程序 |
| 当前调试面是用户点名的那一个 | 对得上 | 开着别的小程序 / 没挂调试 |

**通：** 走「主通道」。本轮不再做环境排查。62000 中途掉了再报一次，仍先问再动。  
**不通：** 走「降级：解包」，不要为环境卡死。

## 交得出就停

缺一项记「无」，不要为凑齐卡死。交得出下面契约 → 立刻进测试：

| 收集物 | 本包 SKILL 当什么 |
|--------|----------------|
| 路由或页面 + URL / 方法 / 参数 | 接口清单 |
| token 在 header / query / body、sign / enc | 钥匙表 |
| appId、API 域名 | 本站面 / `资产/` |
| 盐、硬编码钥、演示号 | JS 钥匙（认钥走 format） |
| 云开发 / `callFunction` | 有入口再打，不另开体系 |

「当前这个指定客户端做完」= 清单已交（或合法降级）+ §4.3 矩阵勾完，不是宇宙级抽干。

## 主通道：MCP 已通时

环境前置过了才走本节。不通 → 「降级：解包」。

MCP 在 **49999**（调工具）；小程序调试面在 **62000**（CDP）。不要把 MCP 连到 62000。

顺序：

1. `connection_ops(action="connect_wmpf")` 连 62000。  
2. `network_ops(action="network_enable")`。  
3. 读 `/home/lotso/artex-ymh/skills/src-method-pack/tools/wmp/e0e1-wx/package/applet_routes/nav_inject.js`，`runtime_ops(action="runtime_eval")` 注入 **page-frame**（不要 `runtime_eval_appservice`）。`typeof window.__routeNavigator` 应为 `"object"`。  
4. `connection_ops(action="select_appservice_context")`。  
5. `network_ops(action="hook_wx_request")`；有 H5 再 `hook_fetch_and_xhr`。  
6. `runtime_ops(action="dump_runtime_snapshot")`。  
7. 能调 `window.__routeNavigator.fetchConfigJson()` 则记下 `pages`。点到 **至少一条业务** `wx.request`（优先订单/地址/资料这类页，不是把全部分包扫完）。  
8. 把 URL / 方法 / 参数、token 位置、sign/enc、host、钥、演示号写入本站清单。详情接口若带了 id，把参数名和样例 id 一并记下当钥匙。  
9. 流量里有 `sign` / `enc` / 硬编码钥，可用 `decrypt_ops` 解明文进钥匙表，然后仍走 HTTP / `dig-scope` §4。认钥走 format。

**停：** 上面契约够了就停。禁止抽干所有路由。空页面刷新最多 2 次。

**禁止：** 在 MCP 里改 id、omit 票、自动打支付/退款/下单；用分析类工具出正式报告；改 Vuex。换 id / 四件套用 curl / Yakit。

## 降级：解包补清单（本篇写完）

MCP 无调试面、WMPF 不通、或拿到的是密文包 → 按下表解包。不要去其它 skill 找 GUI / 长稿。

### 1. 找 `.wxapkg`

先让用户在 PC 微信里打开过点名的那个小程序，再搜该 **appId** 目录下的 `.wxapkg`（主包 `__APP__.wxapkg`、分包各一份，都要）。

Windows 常见位置（按用户目录展开，不要写死 Users 名）：

| 优先 | 路径形态 |
|------|----------|
| 旧版 PC 微信 | `%USERPROFILE%\Documents\WeChat Files\Applet\<appId>\<版本号>\` |
| 新版 / xwechat | `%APPDATA%\Tencent\` 下按 appId 搜 `.wxapkg` |

找不到 → 问用户再打开一次该小程序。

### 2. 解包

输出目录用本任务 `js/miniprogram/<appId>/`，不要留在工具默认 output 里当指针。

```
unveilr "<wxapkg所在目录或文件>" -o "<任务根>/js/miniprogram/<appId>/"
```

没有 `unveilr`：用本机已有的 wxapkg 解包脚本（按文件头 + 索引抽文件）。每个分包各解一次。解失败记「无」，转第 4 步抓包，禁止卡死。

### 3. 抽清单（等于已抽 JS）

从解出目录取，缺的写「无」：

| 文件 | 抽什么 |
|------|--------|
| `app.json` | `pages` / `subPackages` / `tabBar` → 路由 |
| `app-service.js`、分包 `*.js`、`ext.json` / `project.config.json` | `https?://`、`/api/`、`baseURL`、`access_token`、盐、sign、演示号、appId |

只收集。不要在解出的代码里改参当打穿。

### 4. 解包也没有

代理抓微信进程的 HTTPS / `wx.request` 明文，从流量补 URL、方法、参数、票位置。仍缺的记「无」。

### 5. 收口

契约够了（路由或接口 + 票位置，或合法降级）→ 立刻 `dig-scope` §4。不换收集体系。

## 会话 / 登录皮 / 号

- Storage / hook 里拿出的 token 去打 API = **有登录态**。标题走越权，禁止写匿名。复现包写完整票。  
- 微信登录皮不磨（别人的身份页，`dig-scope` §4.1.1）。清单里的 `code2session` / 换票 / 重置走 §4.2.2。  
- 测试微信号与生活号分离；用哪个号点名时明示。

## 同 host

H5 / 小程序打到同一批 API → 一眼差分，无新 path 不重开全矩阵。

## 落盘

任务根仍是 `{任务根}\`。

| 内容 | 位置 |
|------|------|
| 公网 API | `资产/` |
| 抽出的关键 JS | `js/miniprogram/`（禁止只堆 `_dig`，禁止只指向解包工具自己的输出目录） |
| 路由表、钥匙、过程 | `{名}_dig/wxapp/` |
| 正式报告 | `报告/`，只认 format |

优质 API 根域可回灌种子队列；**当前这个指定客户端做完再搜**，不改道。不把小程序当自由跳种子。

## 然后

收集物 = 已经抽过 JS。先短表开场几枪，打完回本站清单；有票走 §4.2.3，没票未授权通了再换 id。CORS 不挖。
