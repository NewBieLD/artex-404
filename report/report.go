// Package report renders a deliverable Markdown report from the exploration
// graph: confirmed findings (with severity/evidence) (docs §15 P5).
//
// 2026-10-13 起报告正文对齐 src-method-pack 的 SRC 漏洞报告版式（rules/vuln-report-format.md，
// 与 src-report-sync 归档标准一致）：每个漏洞一节，标题三行 + 标签段（漏洞描述：/漏洞危害：/
// 涉及接口清单/复现步骤+回包/修复建议），大块之间全角＃分隔。详细报告（reporter 撰写的
// findings.report）非空时原样嵌入，缺失时回退到节点摘要+证据。
package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Input bundles what the report needs.
type Input struct {
	Title       string
	Goal        string
	GeneratedAt time.Time
	AssetCounts map[string]int
	Findings    []*db.Node
	// Reports 按 finding 节点 id 索引的详细报告(findings.report)。非空时该漏洞
	// 一节原样嵌入详细报告（reporter 已按 vuln-report-format 版式撰写）；缺失时
	// 回退为节点摘要 + 证据。
	Reports map[int64]string
}

type findingView struct {
	VulnClass string
	Name      string
	Severity  string
	Summary   string
	PoC       string
	Report    string
	URL       string
}

func parseFinding(n *db.Node) findingView {
	var p struct {
		VulnClass string `json:"vulnclass"`
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Summary   string `json:"summary"`
		Evidence  struct {
			PoC string `json:"poc"`
		} `json:"evidence"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return findingView{p.VulnClass, p.Name, p.Severity, p.Summary, p.Evidence.PoC, "", ""}
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

var sevCN = map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

// urlRe 从摘要/证据里提取第一个 http(s) 链接，作为「目标网站URL」行的兜底来源。
var urlRe = regexp.MustCompile(`https?://[^\s"'<>()\[\]｛｝（）]+`)

func firstURL(parts ...string) string {
	for _, s := range parts {
		if m := urlRe.FindString(s); m != "" {
			return m
		}
	}
	return ""
}

// ── curl → raw HTTP 整包转换 ────────────────────────────────────────────────
// 挖洞 agent 的证据里通常以 curl 命令留痕，而报告版式要求 raw HTTP 请求整包
// （请求行→头→空行→body）。这里做尽力而为的确定性转换：支持 -X/--request、
// -H/--header、-d/--data/--data-raw/--data-binary、-k/-s/--compressed 等常见
// 形态与反斜杠续行；无法解析的命令原样保留。

type curlReq struct {
	method  string
	url     string
	headers []string // 原样 "Name: value"
	body    string
	hasBody bool
}

// splitCurlArgs 把一条 curl 命令拆成参数 token（尊重单双引号与反斜杠续行；
// 续行行首缩进不产生空白 token）。
func splitCurlArgs(cmd string) []string {
	var toks []string
	var cur strings.Builder
	inS, inD, esc := false, false, false
	hasToken := false
	flush := func() {
		if hasToken {
			toks = append(toks, cur.String())
			cur.Reset()
			hasToken = false
		}
	}
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		switch {
		case esc:
			cur.WriteByte(ch)
			esc = false
		case ch == '\\' && !inS:
			// 反斜杠续行：反斜杠与换行一起消费。若分开处理，esc 会残留到
			// 下一行行首的缩进空格上，把空格写进 token（实测 tok=" -d"）。
			if i+1 < len(cmd) && cmd[i+1] == '\n' {
				i++
				continue
			}
			esc = true
		case ch == '\'' && !inD:
			inS = !inS
			hasToken = true
		case ch == '"' && !inS:
			inD = !inD
			hasToken = true
		case (ch == ' ' || ch == '\t' || ch == '\n') && !inS && !inD:
			flush()
		default:
			if ch == ' ' || ch == '\t' {
				if !hasToken {
					continue // 续行行首缩进：不产生空白 token
				}
			}
			cur.WriteByte(ch)
			hasToken = true
		}
	}
	flush()
	return toks
}

func curlToRaw(cmd string) (string, bool) {
	toks := splitCurlArgs(cmd)
	if len(toks) == 0 || toks[0] != "curl" {
		return cmd, false
	}
	var method, url, body string
	var headers []string
	hasBody := false
	for i := 1; i < len(toks); i++ {
		tk := toks[i]
		need := func() string {
			if i+1 < len(toks) {
				i++
				return toks[i]
			}
			return ""
		}
		switch {
		case tk == "-X" || tk == "--request":
			method = need()
		case tk == "-H" || tk == "--header":
			if h := need(); h != "" {
				headers = append(headers, h)
			}
		case tk == "-d" || tk == "--data" || tk == "--data-raw" || tk == "--data-binary" || tk == "--data-urlencode":
			if body == "" {
				body = need()
			}
			hasBody = true
		case strings.HasPrefix(tk, "-"):
			// -k/-s/--compressed 等开关：忽略
		default:
			if url == "" {
				url = tk
			}
		}
	}
	if url == "" {
		return cmd, false
	}
	if i := strings.IndexAny(url, "?#"); i >= 0 {
		_ = i // 保留 query；仅拆 scheme/host 用于 Host 头
	}
	u := strings.TrimSpace(url)
	rest := u
	if i := strings.Index(u, "://"); i >= 0 {
		rest = u[i+3:]
	}
	host, path := rest, "/"
	if i := strings.Index(rest, "/"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	if method == "" {
		if hasBody {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", method, path)
	fmt.Fprintf(&b, "Host: %s\n", host)
	ctSet, cl := false, ""
	for _, h := range headers {
		b.WriteString(h)
		b.WriteString("\n")
		if strings.HasPrefix(strings.ToLower(h), "content-type:") {
			ctSet = true
		}
	}
	if hasBody {
		if !ctSet {
			ctGuess := "application/x-www-form-urlencoded"
			if strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[") {
				ctGuess = "application/json"
			}
			fmt.Fprintf(&b, "Content-Type: %s\n", ctGuess)
		}
		cl = fmt.Sprintf("Content-Length: %d", len(body))
		fmt.Fprintf(&b, "%s\n", cl)
		fmt.Fprintf(&b, "\n%s", body)
	}
	return b.String(), true
}

// transformCurlEvidence 把证据文本里的每一条 curl 命令转成 raw HTTP 整包；
// 命令后面紧跟的「→ …」行作为实际回包摘要，转成「回包：」段。无法识别的
// curl 形态原样保留（不猜）。
func transformCurlEvidence(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "$") // 兼容 "$ curl …" 留痕写法
		trimmed = strings.TrimSpace(trimmed)
		if !strings.HasPrefix(trimmed, "curl ") && trimmed != "curl" {
			out = append(out, line)
			continue
		}
		cmdText := strings.TrimSuffix(trimmed, "\\")
		j := i
		for j+1 < len(lines) && strings.HasSuffix(lines[j], "\\") {
			j++
			cmdText += " " + strings.TrimSuffix(strings.TrimSpace(lines[j]), "\\")
		}
		raw, ok := curlToRaw(cmdText)
		if !ok {
			out = append(out, line)
			continue
		}
		out = append(out, raw)
		// 回包：原证据里 curl 之后紧跟的「→ …」行是实际响应摘要。
		if j+1 < len(lines) {
			next := strings.TrimSpace(lines[j+1])
			if strings.HasPrefix(next, "→") {
				out = append(out, "回包：", strings.TrimPrefix(next, "→"))
				i = j + 1
			} else {
				i = j
			}
		} else {
			i = j
		}
	}
	return strings.Join(out, "\n")
}

// Markdown renders the report. 概览头之后每个漏洞一节，按 vuln-report-format 版式：
// 标题三行（＃漏洞标题 / 目标网站URL / 漏洞等级）→ 漏洞描述： → 详细报告原样嵌入
// （含漏洞危害/涉及接口清单/复现步骤+回包/修复建议）→ 证据回退。
func Markdown(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 渗透测试报告 — %s\n\n", nz(in.Title, "未命名任务"))
	fmt.Fprintf(&b, "- **任务目标**：%s\n", nz(in.Goal, "（未指定）"))
	fmt.Fprintf(&b, "- **生成时间**：%s\n\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))

	// summary
	fmt.Fprintf(&b, "## 摘要\n\n")
	fmt.Fprintf(&b, "- 确认发现：**%d** 个\n", len(in.Findings))
	fmt.Fprintf(&b, "- 资产：")
	var types []string
	for t := range in.AssetCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	for i, t := range types {
		if i > 0 {
			b.WriteString("、")
		}
		fmt.Fprintf(&b, "%s %d", t, in.AssetCounts[t])
	}
	b.WriteString("\n\n")

	// findings
	if len(in.Findings) == 0 {
		fmt.Fprintf(&b, "## 发现\n\n_本次未确认漏洞。_\n\n")
		return b.String()
	}

	fmt.Fprintf(&b, "## 发现\n\n")
	fs := make([]findingView, 0, len(in.Findings))
	for _, n := range in.Findings {
		fv := parseFinding(n)
		if in.Reports != nil {
			fv.Report = in.Reports[n.ID]
		}
		// 详细报告（reporter 撰写）里 HTTP 漏洞的证据常以 curl 命令留痕；
		// 报告版式要求 raw HTTP 整包——渲染层做确定性 curl→raw 转换兜底。
		fv.Report = transformCurlEvidence(fv.Report)
		fv.PoC = transformCurlEvidence(fv.PoC)
		fv.URL = firstURL(fv.Summary, fv.PoC)
		fs = append(fs, fv)
	}
	sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })

	for _, f := range fs {
		title := strings.TrimSpace(nz(f.Name, nz(f.VulnClass, "未命名漏洞")))
		fmt.Fprintf(&b, "＃%s\n", title)
		fmt.Fprintf(&b, "目标网站URL：%s\n", nz(f.URL, "（见复现证据）"))
		fmt.Fprintf(&b, "漏洞等级：%s\n\n", nz(sevCN[f.Severity], strings.ToUpper(nz(f.Severity, "info"))))

		if detail := strings.TrimSpace(f.Report); detail != "" {
			// reporter/update_finding_report 产出的详细报告已按版式含漏洞描述/漏洞危害/
			// 涉及接口清单/复现步骤+回包/修复建议——原样嵌入，不做二次加工。
			b.WriteString(detail)
			if !strings.HasSuffix(detail, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("\n")
			continue
		}

		// 回退：节点只有摘要与证据——按标签段版式输出可得字段。
		if s := strings.TrimSpace(f.Summary); s != "" {
			b.WriteString("漏洞描述：\n")
			b.WriteString(s)
			b.WriteString("\n\n")
		}
		if poc := strings.TrimSpace(f.PoC); poc != "" {
			b.WriteString("＃\n复现证据：\n\n```\n")
			b.WriteString(poc)
			b.WriteString("\n```\n\n")
		}
	}

	return b.String()
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
