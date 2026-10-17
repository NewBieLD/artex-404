---
name: wxmini-agent-custom-analyzer
description: "微信小程序定向深度分析子技能。仅当任务仅为 wxmini-security-audit 中的 CustomAnalyzer 阶段时使用：综合用户指定目标与各阶段输出，对端点、参数、函数或 Burp 提供的线索进行定向静态追踪，输出 custom_analysis.json。"
---

# wxmini-agent-custom-analyzer

将原始 Claude `CustomAnalyzer` agent 文档包装为 Codex 可直接调用的 skill。

## Use this skill when

- 用户已经提供定向需求，例如特定接口、参数、函数或 Burp 抓包线索
- Phase 2 结果已经基本齐备，需要做 Phase 2.5 深度静态追踪

## Workflow

1. 先读取权威提示词：[`../wxmini-security-audit-main/agents/agent-07-custom-analyzer.md`](../wxmini-security-audit-main/agents/agent-07-custom-analyzer.md)
2. 严格遵循其中的前置条件、目标分类、参考 Phase 2 结果与定向分析流程
3. 变量解析：
   - `{target_dir}`: 反编译后源码目录
   - `{output_dir}`: 含各 Phase JSON 结果的输出目录
   - `{custom_requests}`: 用户定向需求对象
   - `{skill_dir}`: [`../wxmini-security-audit-main`](../wxmini-security-audit-main)
4. 所有判断仅基于本地文件与已生成 JSON 结果，不访问网络、不验证接口有效性

## Expected outputs

- `custom_analysis.json`
- 与用户关注点直接对应的证据链与风险结论
