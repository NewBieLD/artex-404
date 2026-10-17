package db

import "fmt"

// taskTemplateSeedFlag gates the one-shot insert of the shipped presets below.
const taskTemplateSeedFlag = "task_templates_builtin_v1"

// builtinTaskTemplate is one shipped penetration-testing preset. The text lands
// verbatim in the create-task form, so each one stays a fill-in-the-blanks brief:
// description states the target and background, goal states the acceptance bar.
// 每条模板内置 src-method-pack 技能结合条款（起手加载技能、按模块路由知识库、
// 报告按 vuln-report-format 落 报告/ 目录供 src-report-sync 归档）与「范围与授权」
// 「漏洞收录口径」两段硬约束，与 src-report-sync 的收录标准对齐。
type builtinTaskTemplate struct {
	name        string
	description string
	goal        string
}

// builtinTaskTemplates are the shipped pentest presets. Insert-if-absent keyed on
// nkey, so a user's rename/edit/delete is never resurrected on restart.
var builtinTaskTemplates = []builtinTaskTemplate{
	{
		name:        "外部 Web 渗透测试",
		description: "目标：{授权目标清单中的 Web 站点}\n类型：互联网暴露的 Web 应用（黑盒，无源码、无账号）\n背景：授权范围内对生产站点开展黑盒渗透，站点含登录、上传、查询等常规业务功能。\n\n要求：\n- 先做信息收集与攻击面梳理（子域、目录、接口、指纹、历史泄露），再按危害排序逐项深入；\n- 覆盖注入、越权、文件操作、SSRF、反序列化、认证与会话缺陷等常见 Web 风险；\n- 每个疑似问题必须给出可复现的最小请求与判定依据，禁止仅凭指纹或报错就判定利用成功。\n\n范围与授权（必读）：\n- 授权目标清单：{授权目标清单，域名/IP 逐条}；排除范围：{排除范围}。仅清单内目标可主动测试，排除范围绝对不可触碰；\n- 子域与关联资产先做归属验证（DNS 解析、证书 SAN、ICP 备案、WHOIS），确认归属后才纳入测试，并调用 add_task_scope 登记到任务范围（平台 RoE 校验以任务范围为准）；\n- 清单外资产、第三方站点（CDN、统计脚本、外链、共宿主机）、归属存疑的子域：只记录不攻击，写入任务工作目录 README 的「待确认」区；\n- 从严判定：同 IP 不同站点、相似域名、合作方系统一律按范围外处理。\n\n漏洞收录口径（必读，与 src-report-sync 归档标准对齐）：\n- 只收「具体漏洞 + 可复现验证证据」：report_finding 的 evidence 必须含最小验证请求与关键回显（或差值、落地文件、调用链 PoC 等等价证明）；traffic_refs 按 baseline/proof/verification 逐条核实后关联，不虚构 ID；\n- 不收：结论性/过程性产出、安全设备管理面公网直暴（只记录不报洞）、已证伪项、无危害的纯信息——这些写入任务工作目录的排除记录，不调 report_finding；\n- 定级按实际影响：critical=严重、high=高危、medium=中危、low=低危，不确定时宁低勿高并注明依据；\n- vulnclass 用固定词表：SQL注入、XSS、越权、未授权访问、信息泄露、认证缺陷、SSRF、RCE、命令注入、文件操作、反序列化、逻辑漏洞、组件漏洞、弱口令；不自造类别名。\n\n技能结合（必读）：\n- 起手调用 Skill 工具加载 `src-method-pack`：先读「安全红线 1～11」并全程遵循（越权最小伤害、禁登出用户会话、CORS 不挖、证明即停、禁 DoS、执行权点到为止），与平台拦截规则冲突时取更严者；\n- 按「对得上再开」只打开命中的知识库模块，禁止通读技能库；`知识库/打穿短表.md` 只读；\n- 专项模块：按目标特征走「对得上再开」全表路由（用户体系→idor/authbypass、上传→file-upload、评论富文本→xss、支付优惠→logic/race-condition、OAuth/JWT→oauth-jwt-test、GraphQL→graphql-test、WAF 拦截→waf-bypass、JS 重前端→js-reverse-guide、401/403→认证口处置）。\n- 正式报告只认 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md` 格式，逐洞写入任务工作目录 `报告/`（文件名=漏洞标题），由 `src-report-sync` 统一对账归档，不要另立格式或位置。",
		goal:        "找出并验证可实际利用的安全问题，按危害排序输出：\n1) 可直接拿到数据或权限的漏洞（含利用链与影响范围）；\n2) 需要组合条件的高危隐患（说明前置条件）；\n3) 明确的攻击路径与修复优先级建议。\n无法验证的猜测单独列出并标注为未证实。\n已证实问题全部按上述报告格式写入 `报告/`（由 `src-report-sync` 统一对账归档）。",
	},
	{
		name:        "API 越权专项",
		description: "目标：{授权 API 基础地址，例如 https://api.example.com}\n类型：REST/GraphQL 接口专项测试\n背景：授权测试账号 {账号A}/{账号B} 已提供，接口有 JWT/Bearer 鉴权。\n\n要求：\n- 先抓取并整理接口清单（含隐藏/文档未列出的接口），确认鉴权方式与参数结构；\n- 重点验证对象级授权（IDOR）、功能级授权（水平/垂直越权）、批量导出与枚举；\n- 用两个不同权限账号交叉对比同一请求的返回差异，作为越权的直接证据。\n\n范围与授权（必读）：\n- 授权目标清单：{授权 API 域名/IP 逐条}；排除范围：{排除范围}。仅清单内接口可主动测试，排除范围绝对不可触碰；\n- 清单外主机、第三方站点、共宿主机：只记录不攻击；\n- 从严判定：同 IP 不同站点、相似域名、网关/负载均衡背后疑似其他业务的一律按范围外处理。\n\n漏洞收录口径（必读，与 src-report-sync 归档标准对齐）：\n- 只收「具体漏洞 + 可复现验证证据」：report_finding 的 evidence 必须含最小验证请求与关键回显（或差值、落地文件、调用链 PoC 等等价证明）；traffic_refs 按 baseline/proof/verification 逐条核实后关联，不虚构 ID；\n- 不收：结论性/过程性产出、安全设备管理面公网直暴（只记录不报洞）、已证伪项、无危害的纯信息——这些写入任务工作目录的排除记录，不调 report_finding；\n- 定级按实际影响：critical=严重、high=高危、medium=中危、low=低危，不确定时宁低勿高并注明依据；\n- vulnclass 用固定词表：SQL注入、XSS、越权、未授权访问、信息泄露、认证缺陷、SSRF、RCE、命令注入、文件操作、反序列化、逻辑漏洞、组件漏洞、弱口令；不自造类别名。\n\n技能结合（必读）：\n- 起手调用 Skill 工具加载 `src-method-pack`：先读「安全红线 1～11」并全程遵循（越权最小伤害、禁登出用户会话、CORS 不挖、证明即停、禁 DoS、执行权点到为止），与平台拦截规则冲突时取更严者；\n- 按「对得上再开」只打开命中的知识库模块，禁止通读技能库；`知识库/打穿短表.md` 只读；\n- 专项模块：idor-test、api-gateway-test、oauth-jwt-test、info-leak-test、type-juggling-test；越权判定必须双账号交叉对比取证。\n- 正式报告只认 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md` 格式，逐洞写入任务工作目录 `报告/`（文件名=漏洞标题），由 `src-report-sync` 统一对账归档，不要另立格式或位置。",
		goal:        "确认接口是否存在越权与数据泄露风险：\n1) 能否用低权限账号访问他人资源或管理功能，给出完整请求与响应证据；\n2) 能否批量拉取敏感数据，估算数据量级；\n3) 输出风险接口清单与修复建议（鉴权检查点落在哪一层）。\n已证实问题全部按上述报告格式写入 `报告/`（由 `src-report-sync` 统一对账归档）。",
	},
	{
		name:        "外网打点转内网纵深",
		description: "目标：{外网入口，例如 https://vpn.example.com}\n类型：完整攻击链（外网突破 → 立足点 → 内网横向）\n背景：授权范围包含该外网入口及其可达内网网段 {内网网段，例如 10.0.0.0/16}。\n\n要求：\n- 外网阶段：优先寻找可直达执行/文件写入的入口，拿到第一台机器控制权；\n- 立足点阶段：稳定会话、收集本机凭据与网络可达信息、确认可行进路线；\n- 内网阶段：先摸清域/工作组结构与高价值目标，再规划最短利用路径。\n\n范围与授权（必读）：\n- 授权目标：{外网入口} 及其可达内网网段 {内网网段}；排除范围：{排除范围} 绝对不可触碰；\n- 起手把确认的外网入口调用 add_task_scope 登记到任务范围；内网阶段每台新主机先确认在范围内再横向，范围外只记录不连接；\n- 新发现的可达网段列入待授权（平台审批流），批准前不延伸测试。\n\n漏洞收录口径（必读，与 src-report-sync 归档标准对齐）：\n- 只收「具体漏洞 + 可复现验证证据」：report_finding 的 evidence 必须含最小验证请求与关键回显（或差值、落地文件、调用链 PoC 等等价证明）；traffic_refs 按 baseline/proof/verification 逐条核实后关联，不虚构 ID；\n- 不收：结论性/过程性产出、安全设备管理面公网直暴（只记录不报洞）、已证伪项、无危害的纯信息——这些写入任务工作目录的排除记录，不调 report_finding；\n- 定级按实际影响：critical=严重、high=高危、medium=中危、low=低危，不确定时宁低勿高并注明依据；\n- vulnclass 用固定词表：SQL注入、XSS、越权、未授权访问、信息泄露、认证缺陷、SSRF、RCE、命令注入、文件操作、反序列化、逻辑漏洞、组件漏洞、弱口令；不自造类别名。\n\n技能结合（必读）：\n- 起手调用 Skill 工具加载 `src-method-pack`：先读「安全红线 1～11」并全程遵循（越权最小伤害、禁登出用户会话、CORS 不挖、证明即停、禁 DoS、执行权点到为止），与平台拦截规则冲突时取更严者；\n- 按「对得上再开」只打开命中的知识库模块，禁止通读技能库；`知识库/打穿短表.md` 只读；\n- 专项模块：recon-methodology（侦察口径）；立足点建立后按 chains-pivot、chains-priv 推进，域环境按 chains-ad。\n- 正式报告只认 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md` 格式，逐洞写入任务工作目录 `报告/`（文件名=漏洞标题），由 `src-report-sync` 统一对账归档，不要另立格式或位置。",
		goal:        "打通外网到内网的完整路径并取得可证明的控制权：\n1) 记录每一跳的入口、利用方式与会话证据；\n2) 明确当前已控制的主机、凭据与可达网段；\n3) 给出继续深入内网的最短路径与所需前置条件。\n已证实问题全部按上述报告格式写入 `报告/`（由 `src-report-sync` 统一对账归档）。",
	},
	{
		name:        "内网渗透（已有立足点）",
		description: "前置：已在 {跳板机 IP} 取得立足点，会话类型 {webshell / 反弹 shell / SSH}。\n目标网段：{内网网段}\n背景：需要从该立足点继续向内网纵深推进，环境含域控/核心业务系统。\n\n要求：\n- 先做立足点加固与信息收集（进程、凭据、会话、路由、可达端口）；\n- 建立稳定隧道后再横向，避免直接暴露操作痕迹；\n- 每台新主机先确认身份与权限，再做提权与凭据收集。\n\n范围与授权（必读）：\n- 授权网段：{内网网段}；排除范围：{排除范围} 绝对不可触碰；\n- 每台新主机先调用 add_task_scope 确认在范围内再横向；范围外主机只记录不连接；\n- 新发现网段/域列入待授权审批，批准前不延伸测试。\n\n漏洞收录口径（必读，与 src-report-sync 归档标准对齐）：\n- 只收「具体漏洞 + 可复现验证证据」：report_finding 的 evidence 必须含最小验证请求与关键回显（或差值、落地文件、调用链 PoC 等等价证明）；traffic_refs 按 baseline/proof/verification 逐条核实后关联，不虚构 ID；\n- 不收：结论性/过程性产出、安全设备管理面公网直暴（只记录不报洞）、已证伪项、无危害的纯信息——这些写入任务工作目录的排除记录，不调 report_finding；\n- 定级按实际影响：critical=严重、high=高危、medium=中危、low=低危，不确定时宁低勿高并注明依据；\n- vulnclass 用固定词表：SQL注入、XSS、越权、未授权访问、信息泄露、认证缺陷、SSRF、RCE、命令注入、文件操作、反序列化、逻辑漏洞、组件漏洞、弱口令；不自造类别名。\n\n技能结合（必读）：\n- 起手调用 Skill 工具加载 `src-method-pack`：先读「安全红线 1～11」并全程遵循（越权最小伤害、禁登出用户会话、CORS 不挖、证明即停、禁 DoS、执行权点到为止），与平台拦截规则冲突时取更严者；\n- 按「对得上再开」只打开命中的知识库模块，禁止通读技能库；`知识库/打穿短表.md` 只读；\n- 专项模块：chains-pivot（隧道与可达）、chains-priv（提权决策）、chains-ad（域内攻击路径）。\n- 正式报告只认 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md` 格式，逐洞写入任务工作目录 `报告/`（文件名=漏洞标题），由 `src-report-sync` 统一对账归档，不要另立格式或位置。",
		goal:        "在目标网段内取得更高价值控制权：\n1) 明确域/工作组结构、关键主机清单与当前权限；\n2) 获取可用于下一跳的凭据或信任关系；\n3) 输出已控制主机与最终可证明的权限边界。\n已证实问题全部按上述报告格式写入 `报告/`（由 `src-report-sync` 统一对账归档）。",
	},
	{
		name:        "漏洞复现与验证",
		description: "目标：{目标地址}\n漏洞线索：{CVE 编号或漏洞描述，例如某组件反序列化}\n类型：已知漏洞的复现与影响验证\n背景：需要确认该组件/接口在当前目标上是否存在，以及是否可达可利用状态。\n\n要求：\n- 先确认版本、配置与组件是否存在，排除蜜罐与伪造响应；\n- 按公开资料构造最小验证载荷，优先使用无破坏性的读取类验证；\n- 对\"看似成功\"的响应做交叉验证（回显内容、文件落地、时间盲注差值）。\n\n范围与授权（必读）：\n- 仅对 {目标地址} 本身开展复现验证；不延伸到关联资产、CDN 源站、云函数等托管设施，不触碰 {排除范围}；\n- 发现漏洞实际影响范围超出目标时只记录范围结论，不做延伸验证。\n\n漏洞收录口径（必读，与 src-report-sync 归档标准对齐）：\n- 只收「具体漏洞 + 可复现验证证据」：report_finding 的 evidence 必须含最小验证请求与关键回显（或差值、落地文件、调用链 PoC 等等价证明）；traffic_refs 按 baseline/proof/verification 逐条核实后关联，不虚构 ID；\n- 不收：结论性/过程性产出、安全设备管理面公网直暴（只记录不报洞）、已证伪项、无危害的纯信息——这些写入任务工作目录的排除记录，不调 report_finding；\n- 定级按实际影响：critical=严重、high=高危、medium=中危、low=低危，不确定时宁低勿高并注明依据；\n- vulnclass 用固定词表：SQL注入、XSS、越权、未授权访问、信息泄露、认证缺陷、SSRF、RCE、命令注入、文件操作、反序列化、逻辑漏洞、组件漏洞、弱口令；不自造类别名。\n\n技能结合（必读）：\n- 起手调用 Skill 工具加载 `src-method-pack`：先读「安全红线 1～11」并全程遵循（越权最小伤害、禁登出用户会话、CORS 不挖、证明即停、禁 DoS、执行权点到为止），与平台拦截规则冲突时取更严者；\n- 按「对得上再开」只打开命中的知识库模块，禁止通读技能库；`知识库/打穿短表.md` 只读；\n- 专项模块：sqlmap-syntax-gen（注入类仅生成最小伤害命令）、injection-test；严守红线 6/8：证明即停、不拖库、不拿 shell。\n- 正式报告只认 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md` 格式，逐洞写入任务工作目录 `报告/`（文件名=漏洞标题），由 `src-report-sync` 统一对账归档，不要另立格式或位置。",
		goal:        "给出漏洞是否真实可利用的明确结论：\n1) 存在性证据（指纹、版本、可达性）；\n2) 利用成功证据（命令回显、文件读取内容或等价证明）；\n3) 若不可利用，说明卡点（WAF、补丁、网络隔离）与绕过可能性。\n已证实问题全部按上述报告格式写入 `报告/`（由 `src-report-sync` 统一对账归档）。",
	},
	{
		name:        "资产面测绘与攻击面梳理",
		description: "目标：{主域名或 IP 段}\n类型：大规模资产测绘（只做发现与画像，不做深度利用）\n背景：需要对授权范围做一次完整资产盘点，输出可用于后续测试的目标清单。\n\n要求：\n- 子域、端口、Web 服务、指纹、组件版本全面覆盖；\n- 对存活资产做规范化识别，合并重复与跳转；\n- 标注暴露在公网的敏感服务与高风险组件。\n\n范围与授权（必读）：\n- 授权范围：{主域名或 IP 段}；排除范围：{排除范围}。仅范围内做发现与画像；\n- 子域/关联资产先做归属验证（DNS 解析、证书 SAN、ICP 备案、WHOIS），归属存疑的单独标注「待确认」，不主动深入；\n- 从严判定：同 IP 不同站点、相似域名一律标注为疑似范围外。\n\n漏洞收录口径（必读，与 src-report-sync 归档标准对齐）：\n- 只收「具体漏洞 + 可复现验证证据」：report_finding 的 evidence 必须含最小验证请求与关键回显（或差值、落地文件、调用链 PoC 等等价证明）；traffic_refs 按 baseline/proof/verification 逐条核实后关联，不虚构 ID；\n- 不收：结论性/过程性产出、安全设备管理面公网直暴（只记录不报洞）、已证伪项、无危害的纯信息——这些写入任务工作目录的排除记录，不调 report_finding；\n- 定级按实际影响：critical=严重、high=高危、medium=中危、low=低危，不确定时宁低勿高并注明依据；\n- vulnclass 用固定词表：SQL注入、XSS、越权、未授权访问、信息泄露、认证缺陷、SSRF、RCE、命令注入、文件操作、反序列化、逻辑漏洞、组件漏洞、弱口令；不自造类别名。\n\n技能结合（必读）：\n- 起手调用 Skill 工具加载 `src-method-pack`：先读「安全红线 1～11」并全程遵循（越权最小伤害、禁登出用户会话、CORS 不挖、证明即停、禁 DoS、执行权点到为止），与平台拦截规则冲突时取更严者；\n- 按「对得上再开」只打开命中的知识库模块，禁止通读技能库；`知识库/打穿短表.md` 只读；\n- 专项模块：recon-methodology、subdomain-takeover-test、info-leak-test；只做发现与画像，不做深度利用。\n- 正式报告只认 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md` 格式，逐洞写入任务工作目录 `报告/`（文件名=漏洞标题），由 `src-report-sync` 统一对账归档，不要另立格式或位置。",
		goal:        "输出结构化资产清单与风险分级：\n1) 全部存活资产（域名/IP/端口/服务/指纹）；\n2) 高风险暴露面清单及排序理由；\n3) 建议优先测试的目标与对应攻击方向。\n已证实问题全部按上述报告格式写入 `报告/`（由 `src-report-sync` 统一对账归档）。",
	},
	{
		name:        "白盒 0day 审计",
		description: "目标：{源码 / 项目根目录}\n类型：白盒源码审计（0day / 高危漏洞挖掘）\n背景：已获得目标项目源码或反编译产物（授权审计），需要从代码层面挖掘可实际利用的安全问题。\n\n要求：\n- 按 rules/researcher-blackbox-whitebox.md 的 Phase 0～6 执行：先建运行环境与调用链认知，再定向审计；\n- 优先攻击面：外部可达入口（路由、接口、反序列化点、模板渲染、文件操作、权限边界），每条结论标注调用链可达性证据；\n- 每个问题必须给出「污染源 → 传播路径 → 危险函数」完整链路与最小验证 PoC，禁止仅凭危险函数模式匹配报洞。\n\n范围与授权（必读）：\n- 仅审计 {源码 / 项目根目录} 给定路径内的代码与构建产物；不做网络探测，不对任何线上系统发起请求；\n- 依赖的第三方组件与外部服务仅作记录，不在本任务测试范围内。\n\n漏洞收录口径（必读，与 src-report-sync 归档标准对齐）：\n- 只收「具体漏洞 + 可复现验证证据」：report_finding 的 evidence 必须含最小验证请求与关键回显（或差值、落地文件、调用链 PoC 等等价证明）；traffic_refs 按 baseline/proof/verification 逐条核实后关联，不虚构 ID；\n- 不收：结论性/过程性产出、安全设备管理面公网直暴（只记录不报洞）、已证伪项、无危害的纯信息——这些写入任务工作目录的排除记录，不调 report_finding；\n- 定级按实际影响：critical=严重、high=高危、medium=中危、low=低危，不确定时宁低勿高并注明依据；\n- vulnclass 用固定词表：SQL注入、XSS、越权、未授权访问、信息泄露、认证缺陷、SSRF、RCE、命令注入、文件操作、反序列化、逻辑漏洞、组件漏洞、弱口令；不自造类别名。\n\n技能结合（必读）：\n- 起手调用 Skill 工具加载 `src-method-pack`：先读「安全红线 1～11」并全程遵循（越权最小伤害、禁登出用户会话、CORS 不挖、证明即停、禁 DoS、执行权点到为止），与平台拦截规则冲突时取更严者；\n- 按「对得上再开」只打开命中的知识库模块，禁止通读技能库；`知识库/打穿短表.md` 只读；\n- 专项模块：rules/researcher-blackbox-whitebox.md（Phase 0～6 主流程）、chains-rev（逆向切入）、chains-pwn（二进制利用）。\n- 正式报告只认 `/home/lotso/artex-ymh/skills/src-method-pack/rules/vuln-report-format.md` 格式，逐洞写入任务工作目录 `报告/`（文件名=漏洞标题），由 `src-report-sync` 统一对账归档，不要另立格式或位置。",
		goal:        "产出可复核的白盒审计结论：\n1) 已证实可利用的 0day / 高危问题（完整调用链 + 最小 PoC）；\n2) 高危隐患清单与利用前置条件；\n3) 修复建议与优先级排序。\n未经完整链路验证的猜测单列并标注为未证实。\n已证实问题全部按上述报告格式写入 `报告/`（由 `src-report-sync` 统一对账归档）。",
	},
}

// seedBuiltinTaskTemplates inserts the shipped pentest presets once on first
// startup. The settings flag keeps a user's later rename/edit/delete from being
// resurrected on restart; nkey conflict means "user already has this name" and
// is skipped silently.
func (d *DB) seedBuiltinTaskTemplates() error {
	if v, _, _ := d.GetSetting(taskTemplateSeedFlag); v == "done" {
		return nil
	}
	for _, t := range builtinTaskTemplates {
		if _, err := d.Exec(`
INSERT INTO task_templates(name, nkey, description, goal)
VALUES ($1, $2, $3, $4)
ON CONFLICT (nkey) DO NOTHING`,
			t.name, taskTemplateNKey(t.name), t.description, t.goal); err != nil {
			return fmt.Errorf("template %q: %w", t.name, err)
		}
	}
	return d.SetSetting(taskTemplateSeedFlag, "done")
}
