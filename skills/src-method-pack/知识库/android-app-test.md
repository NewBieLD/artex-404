# Android App 收集（指定才开）

> **只收集。** 测、定级、报告全部走本包 SKILL（`dig-scope` §4 + `vuln-report-format`）。  
> 主线是 HTTP 面。iOS 不在本篇。

## 何时开 / 何时不开

| 开 | 不开 |
|----|------|
| 用户**点名了** APK / 包名 / 具体 Android 应用 | 只挖集团 / 只挖 Web，没点名 App |
| 用户另说「带出也跟」之后，才跟 Web 里的 APK/包名 | Web/JS 带出 APK 下载、包名 → **记下不跟** |
| — | 应用商店搜品牌当种子；把集团名当 App 任务 |

点名必须是具体客户端，不是集团名。

## 两段不要混

| 段 | 做 | 不做 |
|----|----|------|
| **收集**（本篇） | pull/解包出 host/钥；过钉死后抓明文；token 位置、sign/enc | 不在 Frida 里改参打穿当主路径 |
| **测试**（本包 SKILL） | 收集物当清单+钥匙，走 `dig-scope` §4 | 不把「再 dump 一轮」当进站准入 |

点页面、出请求 = 收集。换 id、omit 票、四件套 = curl / Yakit。

## 环境前置检测（开场一次）

点名 App 且说「动」之后，**先只读检查，再收集**。本轮只做这一次。

只读查：

| 查 | 过 | 问题（要问） |
|----|----|--------------|
| `adb devices` 有 `device` | 通 | 没设备 / unauthorized / 无线端口变了 |
| `adb shell id` 是 `uid=0` | 通 | 非 root |
| `settings get global http_proxy` | 空 / `:0` / `null` | 有残留代理 |
| PC `frida --version` 与手机 `/data/local/tmp/frida-server` 版本 | 一致 | 对不上 / 文件不在 |
| 用户店 Yakit 证书 | 已在 | 没有 |

**有问题：** 列出来问用户，**确认后再调整**。未确认禁止改（含换无线 IP 去 `adb connect`、换版本起停 frida-server、清代理、装证书、改 settings）。
**没问题：** 立刻进下面收集顺序；**本轮不再做环境排查、不再改环境、对话里不再提环境**。中途通道真断了（adb 掉线）才再报一次，仍先问再动。

**永久禁写（不问也不许做）：** 手机全局 `http_proxy` / `global_http_proxy`、iptables、hosts、dns、Wi‑Fi 代理。抓包由用户在手机上手动指 Yakit，测完用户自己清。只读发现残留 → 当问题问用户，禁止 `settings put/delete`。

过门之后的收集动作（起本轮 frida-server、pull 该包 APK）不算「改环境」，按落地顺序做即可。其它写（往手机 push 文件、装证书、改全局 settings）仍先问。

## 交得出就停

缺一项记「无」。交得出下面契约 → 立刻进测试：

| 收集物 | 本包 SKILL 当什么 |
|--------|----------------|
| 路由或页面 + URL / 方法 / 参数 | 接口清单 |
| token 在 header / query / body、sign / enc | 钥匙表 |
| 包名、API 域名 | 本站面 / `资产/` |
| 盐、硬编码钥、演示号 | JS 钥匙（认钥走 format） |
| 钉死是否过掉、深链打到的 URL | 能不能按普通 HTTP 打；有业务请求再进清单 |

钉死过不去仍要交静态 host/钥匙；明文流量记降级。禁止卡死等 Frida 抽干。

## 主通道：ADB + 已 root 机 + Frida

连上之后 pull / shell / 推 frida-server **同一套**（有线或无线只差怎么连）。

本机环境（这台电脑、这部手机；开场用上面前置检测对一次，过了本轮不再核。对不上不要盲连表里的无线 IP）：

| 项 | 值 |
|----|-----|
| ADB | `C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe`（不在系统 PATH） |
| 无线 | 曾 `172.20.10.4:32801`，IP/端口会变；变了算环境问题，问用户，确认后再 `adb connect` |
| 机 | PKR110，Android 16，arm64-v8a，KernelSU（`adb shell` 已是 uid=0） |
| PC Frida | 17.15.4 |
| 手机 frida-server | `/data/local/tmp/frida-server` **17.15.4**（旧版 `frida-server.17.9.3.bak`）；**默认没起**（过门后起本轮进程，不算改环境） |
| jadx / apktool | `{任务根}\_tools\bin\` 下 `jadx.cmd` / `apktool.cmd`（包装钉 JDK 23）。系统 PATH 里的 `java` 是 8，**不要**走它 |
| Yakit 证书 | 用户店已有 `10fb1fcc.0` = Yakit MITM Root CA |
| 系统 HTTP 代理 | **禁写**。只读；残留当问题问用户。抓包用户自己在手机上指 Yakit |
| objection | 未装，非必须 |

落地顺序（说「动」且已点名 App 才执行；**环境前置过了才走**）：

1. 起 `/data/local/tmp/frida-server`（版本与 PC 一致）  
2. pull 该包 APK  
3. jadx / apktool 出 host / 钥 / 深链  
4. 用户已配好抓包时再收明文；钉死则 Frida unpin。**禁止** agent 写手机代理  
5. 交清单 → 本包 SKILL  

无线断了：当环境问题再报一次，问用户 USB 还是新端口，确认后再连。

## 降级

钉死过不去 → 仍交静态 host/钥匙，明文记降级，测试仍本包 SKILL。

## 本地面

导出组件、Deeplink、本地库明文：**能打到别人数据或进号**才按 format 写。主线仍是 HTTP。只害本机、碰不到他人业务 → 不写。

## 会话 / 号

- 包 / hook 里拿出的 token 去打 API = **有登录态**。标题走越权，禁止写匿名。  
- 系统账号页 / 第三方登录皮不磨；清单里的发会话 / 换票 / 重置走 §4.2.2。  
- 测试账号，不要用生活号登目标 App。

## 同 host

H5 / App 打到同一批 API → 一眼差分，无新 path 不重开全矩阵。

## 落盘

任务根仍是 `{任务根}\`。

| 内容 | 位置 |
|------|------|
| 公网 API | `资产/` |
| 抽出的关键代码/配置 | `js/app/` |
| 路由表、钥匙、apk 过程 | `{名}_dig/apk/` |
| 正式报告 | `报告/`，只认 format |

优质 API 根域可回灌种子队列；**当前这个指定客户端做完再搜**，不改道。不把 App 当自由跳种子。

## 然后

收集物 = 已经抽过 JS。先短表开场几枪，打完回本站清单；有票走 §4.2.3，没票未授权通了再换 id。CORS 不挖。
