---
name: wxmini-agent-endpoint-miner
description: "微信小程序接口智能分析子技能。仅当任务仅为 wxmini-security-audit 中的 EndpointMiner 阶段时使用：读取 raw_endpoints.json、关联 BaseURL 与路径片段、标准化端点并输出 api_endpoints.json。"
---

# wxmini-agent-endpoint-miner

将原始 Claude `EndpointMiner` agent 文档包装为 Codex 可直接调用的 skill。

## Use this skill when

- 用户只需要微信小程序接口提取后的智能关联分析
- 已有 `raw_endpoints.json`，需要继续完成接口归一化、BaseURL 关联和方法推断

## Workflow

1. 先读取权威提示词：[`../wxmini-security-audit-main/agents/agent-03-endpoint-miner.md`](../wxmini-security-audit-main/agents/agent-03-endpoint-miner.md)
2. 保持其中的门禁条件、BaseURL 关联、封装函数识别、按文件分析与去重规范
3. 变量解析：
   - `{target_dir}`: 反编译后源码目录
   - `{output_dir}`: 含 `raw_endpoints.json` 与 `file_inventory.json` 的输出目录
   - `{skill_dir}`: [`../wxmini-security-audit-main`](../wxmini-security-audit-main)
4. 只做静态关联分析，不探测接口连通性，不发送网络请求

## Expected outputs

- `api_endpoints.json`
- 按域名、方法、来源文件归类的接口结果
