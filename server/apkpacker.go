// apkpacker.go 是 apk_packer_check host 工具:APK 加固(壳)识别,特征表
// 移植自全链哨兵 11ee8e99 的 PACKER_SIGNATURES(10 家厂商,libs 匹配 so 文件
// 名、classes 匹配 smali/dex 里的类名痕迹)。输入两种形态:
//   - apktool/jadx 反编译目录(so 清单 + smali 文本/路径扫描,哨兵同款语义)
//   - .apk/.zip 文件(zip 条目名 + classes*.dex 原始字节里的类名字符串)
//   - 单个 .dex 文件(字节扫描)
// 输出结构化 JSON(命中厂商、证据、so 清单、行动指引),worker 可把加固
// 状态写成任务事实/finding;命中时指引先 droid_unpack 再反编译。
package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// packerSignature 一条加固厂商特征:libs 打 so 文件名,classes 打类名痕迹
// (smali 路径/内容,或 dex 原始字节里的字符串池)。
type packerSignature struct {
	vendor  string
	libs    *regexp.Regexp
	classes *regexp.Regexp
}

// packerSignatures 与哨兵 11ee8e99 的 PACKER_SIGNATURES 逐条对应。
var packerSignatures = []packerSignature{
	{vendor: "梆梆安全 (Bangcle/SecNeo)",
		libs:    regexp.MustCompile(`(?i)lib(DexHelper|SecShell|ExecHelper|baksmali|DexProtector)`),
		classes: regexp.MustCompile(`(?i)com\.secneo\.apkwrapper|com\.secneo\.SApplication`)},
	{vendor: "360 加固保 (Jiagu)",
		libs:    regexp.MustCompile(`(?i)libjiagu(_a|_x86|_art)?\.so|libjiagu\.so`),
		classes: regexp.MustCompile(`(?i)com\.qihoo\.util|com\.stub\.StubApp`)},
	{vendor: "腾讯乐固 (Legu)",
		libs:    regexp.MustCompile(`(?i)libshella-\d|libshellx-\d|libBugly\.so|libtup\.so|libexec\.so`),
		classes: regexp.MustCompile(`(?i)com\.tencent\.StubShell|s\.h\.e\.l\.l`)},
	{vendor: "爱加密 (Ijiami)",
		libs:    regexp.MustCompile(`(?i)libexecmain\.so|ijiami\.dat|libexec\.so`),
		classes: regexp.MustCompile(`(?i)s\.h\.e\.l\.l|com\.shell\.SuperApplication`)},
	{vendor: "娜迦 (Nagoo)",
		libs:    regexp.MustCompile(`(?i)libkwssgmain\.so|libkwscmm\.so|libkwscr\.so`),
		classes: regexp.MustCompile(`(?i)com\.nagoo|kwsapp`)},
	{vendor: "百度加固",
		libs:    regexp.MustCompile(`(?i)libbaiduprotect\d*\.so`),
		classes: regexp.MustCompile(`(?i)com\.baidu\.protect`)},
	{vendor: "腾讯 TP / ACE",
		libs:    regexp.MustCompile(`(?i)libtprt\.so|libNSaferOnly\.so`),
		classes: regexp.MustCompile(`(?i)com\.tencent\.tpmobile`)},
	{vendor: "网易易盾",
		libs:    regexp.MustCompile(`(?i)libnesec\.so|libexecmixed\.so`),
		classes: regexp.MustCompile(`(?i)com\.netease\.nis\.shell`)},
	{vendor: "DexProtector",
		libs:    regexp.MustCompile(`(?i)libdexprotector`),
		classes: regexp.MustCompile(`(?i)dexprotector`)},
	{vendor: "几维 (Kiwi)",
		libs:    regexp.MustCompile(`(?i)libkwmmain\.so|kdpdata\.so`),
		classes: regexp.MustCompile(`(?i)com\.kiwisec`)},
}

const (
	packerScanTextCap = 8 * 1024 * 1024  // smali/文本扫描总上限
	packerScanFileCap = 512 * 1024       // 单文件读取上限
	packerDexCap      = 256 * 1024 * 1024 // dex 原始字节总上限
)

// packerEvidence 一条命中证据。
type packerEvidence struct {
	Vendor string   `json:"vendor"`
	Hits   []string `json:"hits"`
}

// detectPacker 对目录/apk/dex 做加固识别。返回 (是否加固, 命中列表, so 清单, 备注)。
func detectPacker(path string) (bool, []packerEvidence, []string, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, nil, nil, "", err
	}
	var soFiles []string
	var haystack strings.Builder
	var note string
	mode := "dir"

	switch {
	case st.IsDir():
		mode = "dir"
		var textUsed int64
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, werr error) error {
			if werr != nil || d == nil {
				return nil
			}
			rel, rerr := filepath.Rel(path, p)
			if rerr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			haystack.WriteString(rel)
			haystack.WriteByte('\n')
			if d.IsDir() {
				return nil
			}
			if strings.HasSuffix(rel, ".so") && (strings.Contains(rel, "/lib/") || strings.HasPrefix(rel, "lib/")) {
				soFiles = append(soFiles, rel)
			}
			// smali 与 src 下的文本(哨兵 grep res/smali* 与 src 的语义);
			// 路径本身已进 haystack,内容再补一层防路径形态差异。
			if (strings.Contains(rel, "/smali") || strings.HasPrefix(rel, "smali") || strings.Contains(rel, "/src/") || strings.HasPrefix(rel, "src/")) &&
				textUsed < packerScanTextCap {
				f, oerr := os.Open(p)
				if oerr != nil {
					return nil
				}
				defer f.Close()
				limited := io.LimitReader(f, packerScanFileCap)
				n, _ := io.Copy(&haystack, limited)
				textUsed += n
				haystack.WriteByte('\n')
			}
			return nil
		})
		if err != nil {
			return false, nil, nil, "", err
		}
	case strings.HasSuffix(strings.ToLower(path), ".apk") || strings.HasSuffix(strings.ToLower(path), ".zip"):
		mode = "apk"
		zr, zerr := zip.OpenReader(path)
		if zerr != nil {
			return false, nil, nil, "", zerr
		}
		defer zr.Close()
		var dexUsed int64
		for _, entry := range zr.File {
			haystack.WriteString(entry.Name)
			haystack.WriteByte('\n')
			if strings.HasSuffix(entry.Name, ".so") && strings.Contains(entry.Name, "lib/") {
				soFiles = append(soFiles, entry.Name)
			}
			if strings.HasPrefix(entry.Name, "classes") && strings.HasSuffix(entry.Name, ".dex") &&
				dexUsed < packerDexCap && entry.FileInfo().Size() <= packerDexCap {
				f, oerr := entry.Open()
				if oerr != nil {
					continue
				}
				n, _ := io.Copy(&haystack, io.LimitReader(f, packerDexCap))
				dexUsed += n
				_ = f.Close()
			}
		}
		note = "apk 模式:so 条目名 + dex 字符串池扫描;smali 级判定需反编译目录模式"
	default:
		mode = "dex"
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return false, nil, nil, "", rerr
		}
		haystack.Write(data)
		note = "单文件模式:字节级类名痕迹扫描"
	}

	hay := haystack.String()
	// smali/dex 里的类名是斜杠形态(Lcom/stub/StubApp;),特征表是点分形态
	// (哨兵靠 grep 的斜杠 pattern 兜;Go 侧统一把 haystack 做一份斜杠→点分
	// 的变体,两种形态各测一遍)。
	dotHay := strings.ReplaceAll(hay, "/", ".")
	var hits []packerEvidence
	for _, sig := range packerSignatures {
		var ev []string
		for _, so := range soFiles {
			if sig.libs.MatchString(so) {
				ev = append(ev, filepath.Base(so))
			}
		}
		m := sig.classes.FindString(hay)
		if m == "" {
			m = sig.classes.FindString(dotHay)
		}
		if m != "" {
			ev = append(ev, clampString(strings.TrimSpace(m), 80))
		}
		if len(ev) > 0 {
			if len(ev) > 3 {
				ev = ev[:3]
			}
			hits = append(hits, packerEvidence{Vendor: sig.vendor, Hits: ev})
		}
	}
	_ = mode
	return len(hits) > 0, hits, soFiles, note, nil
}

// apkPackerCheckTool 加固识别 host 工具(不需要设备,静态检查)。
func (s *Server) apkPackerCheckTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "apk_packer_check",
		Description: "识别 APK 是否加固(壳)及厂商:梆梆/SecNeo、360 加固保、腾讯乐固、爱加密、娜迦、百度、腾讯 TP/ACE、" +
			"网易易盾、DexProtector、几维。输入 apktool/jadx 反编译目录(so 清单 + smali 扫描,最准)或 .apk/.zip 文件" +
			"(zip 条目 + dex 字符串池)或单个 .dex。命中加固时必须先 droid_unpack 内存脱壳再反编译," +
			"直接反编译 base.apk 只会得到壳代码。结果为结构化 JSON,建议把加固厂商写入任务事实。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": strParam("反编译目录或 .apk/.zip/.dex 文件路径(相对工作目录或绝对路径)"),
			},
			"required": []any{"path"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: devicePerm,
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Path string `json:"path"`
			}
			_ = json.Unmarshal(in, &a)
			p := strings.TrimSpace(a.Path)
			if p == "" {
				return actool.Errorf("path 必填"), nil
			}
			if !filepath.IsAbs(p) {
				p = filepath.Join(s.toolWorkDir(tc), p)
			}
			hardened, hits, soFiles, note, err := detectPacker(p)
			if err != nil {
				return actool.Errorf("识别失败: " + err.Error()), nil
			}
			out := map[string]any{
				"ok": true, "hardened": hardened, "path": p,
				"hits": hits, "so_seen": clampStrings(soFiles, 8), "so_count": len(soFiles),
			}
			if note != "" {
				out["note"] = note
			}
			var text string
			if hardened {
				var lines []string
				for _, h := range hits {
					lines = append(lines, fmt.Sprintf("%s:命中 %s", h.Vendor, strings.Join(h.Hits, "、")))
				}
				text = strings.Join(lines, "\n") +
					"\n→ 检测到加固:直接反编译 base.apk 只能得到壳代码,先 droid_unpack 脱壳再反编译 dump 出的 dex"
				out["hint"] = "先 droid_unpack 内存脱壳,再反编译 dump 出的 dex(优先最大的几个)"
			} else if len(soFiles) == 0 {
				text = "未发现 native 库(纯 Java/Kotlin 或未解出资源);未见已知加固特征"
			} else {
				text = "未发现已知加固特征(lib 下:" + strings.Join(clampStrings(soFiles, 8), "、") +
					")。若反编译结果明显异常(空壳/类名错乱),仍可尝试 droid_unpack"
			}
			out["summary"] = text
			return jsonResult(out)
		},
	})
}

func clampStrings(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return ss[:n]
}
