# 知识库索引

实战方法论 / 测试清单 / 场景矩阵。与 `SKILL.md` 流程配合使用。

## 使用约定

- 进站先读 `打穿短表.md`；对得上再打开对应模块看细节。文件不长就整篇开；超长篇可先开点名节，不够就继续开。禁止每站通读本目录
- 磁盘有 `*src经验.md` 才开专篇，没有不算缺。开 `SKILL.md` 不会再带集团日记
- 短表和「注入/SSRF/XSS/RCE」都不是上限。本站过全类型矩阵；四件套打在有差分面上（防空窗），不是只测这四类，也不是每个 path 喷 `'`。有会话时越权/逻辑与四件套同硬（`dig-scope` §4.2.3）
- 方便和能力优先；省 token 是顺带，不挡开模块
- 短表点名的手法用标题搜。有指针的肥篇只留实战中文 + 指针段；禁开/几乎不交的篇已收成一行。手法行不删、算成不改矮。
- 篇内跳转已改成本目录真实文件（`idor-test.md` 一类）；不要再跟 `../xxx/SKILL.md`
- 与 `/home/lotso/artex-ymh/skills/src-method-pack/rules` 冲突时 **以 rules 为准**（挖什么 `src-value`；CORS 不挖；写不写 `vuln-report-format`）
- CORS 不挖；禁开越狱教材；禁止磨登录 HTML。包内无对应模块。
- 正式 SRC 报告：`/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md`

## 文件清单

| 文件 | 说明 |
|------|------|
| `打穿短表.md` | 挖洞手法索引（本包只读；拟进写任务根 dig） |
| `api-gateway-test.md` | API 网关 |
| `agent-tool-exec-test.md` | 对话口工具真执行（不是越狱、不是云 IDE RPC） |
| `android-app-test.md` | Android App**收集**（用户指定才开；测仍本包 SKILL） |
| `authbypass-test.md` | 认证绕过（未登录改密/IDaaS + 短表指针；英文字典已砍） |
| `cache-poisoning-test.md` | 缓存投毒/欺骗（中文主线 + 附件） |
| `clickjacking-test.md` | 缺头不写（已收成一行） |
| `cloud-ide-codex-rce-chain.md` | 云 IDE/Codex 系：弱口令→RPC RCE→集群/API Key 链（短表有指针） |
| `crlf-injection-test.md` | 几乎不交（已收成一行） |
| `csp-bypass-test.md` | 几乎不交（已收成一行）；XSS 走 `xss-test.md` |
| `csrf-test.md` | 专题知识 |
| `csv-formula-injection-test.md` | 几乎不交（已收成一行） |
| `dangling-markup-test.md` | 几乎不交（已收成一行） |
| `dependency-confusion-test.md` | 几乎不交（已收成一行） |
| `deserialization-test.md` | 专题知识 |
| `dns-rebinding-test.md` | 几乎不交（已收成一行）；SSRF 走 `ssrf-test.md` |
| `el-injection-test.md` | 专题知识 |
| `email-header-injection-test.md` | 几乎不交（已收成一行） |
| `file-upload-test.md` | 文件上传（STS/列桶/分享鉴权等指针） |
| `ghost-bits-cast-test.md` | Ghost Bits 原理+常用字+公式；逐字节两套表已砍 |
| `graphql-test.md` | GraphQL |
| `hpp-test.md` | 几乎不交（已收成一行） |
| `http-host-header-test.md` | 专题知识 |
| `http-smuggling-test.md` | 请求走私（中文主线 + H2 附件） |
| `http2-attacks-test.md` | 几乎不交（已收成一行）；走私走 `http-smuggling-test.md` |
| `idor-test.md` | 越权（中文主线 + 短表指针） |
| `info-leak-test.md` | 信息泄露 |
| `injection-test.md` | 注入（OR+total / 邮件订阅 iframe / SSTI；确认 SQLi 给 sqlmap；英文百科已砍） |
| `insecure-scm-test.md` | 专题知识 |
| `jndi-injection-test.md` | 专题知识 |
| `js-reverse-guide.md` | JS 逆向 |
| `logic-test.md` | 业务逻辑（支付/流程 + 商家促销绑定） |
| `miniprogram-test.md` | 微信小程序**收集**（用户指定才开；测仍本包 SKILL） |
| `oauth-jwt-test.md` | OAuth/JWT/SAML/OIDC |
| `open-redirect-test.md` | 专题知识 |
| `path-traversal-lfi-test.md` | 专题知识 |
| `prototype-pollution-test.md` | 专题知识 |
| `race-condition-test.md` | 竞态（中文主线 + 同步手法附件） |
| `recon-methodology.md` | 侦察方法论 |
| `ruishu-re-test.md` | 瑞数 412 特征；可选项目外置适配器短生命周期尝试；未绑定时记墙止损 |
| `sqlmap-syntax-gen.md` | sqlmap 语法生成（手工确认差分后才用；最小伤害口径） |
| `ssrf-test.md` | SSRF（IMDS 路径差 / GOPROXY / 对象存储回源） |
| `subdomain-takeover-test.md` | 专题知识 |
| `type-juggling-test.md` | 专题知识 |
| `waf-bypass.md` | WAF 绕过 |
| `websocket-test.md` | WebSocket（中文主线 + 走私/Socket.IO 附件） |
| `xslt-injection-test.md` | 几乎不交（已收成一行） |
| `xss-test.md` | XSS（中文开场 + 冷门事件 + XSS→RCE / 自定义协议） |
| `xxe-test.md` | 专题知识 |

**合计：** 以本目录实际 `.md` 为准（不含本 README）。CORS 不挖、禁开越狱、禁止磨登录 HTML，包内无对应模块。SRC 报告版式见 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md`。定级只认 format。
