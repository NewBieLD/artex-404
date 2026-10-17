package agent

import (
	"strings"
	"testing"
)

// 批 5 B1:反 AI 蜜罐红线是代码固定尾——非内网 worker 必含红线段,内网 worker
// 两段(反 AI 红线 + 内网红线)都在;DB 编辑正文覆盖不掉红线段。
func TestWorkerSystemAntiTrapRules(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil

	// 非内网:含反 AI 红线,不含内网红线。
	ext := workerSystem("", "", "/data", "/data", false, false)
	if !strings.Contains(ext, "反 AI 蜜罐红线") {
		t.Fatalf("non-intranet worker missing anti-trap rules: %q", ext)
	}
	if strings.Contains(ext, "内网红线") {
		t.Fatalf("non-intranet worker must not append 内网红线尾: %q", ext)
	}

	// 内网:两段红线都在。
	in := workerSystem("", "", "/data", "/data", true, false)
	if !strings.Contains(in, "反 AI 蜜罐红线") || !strings.Contains(in, "内网红线") {
		t.Fatalf("intranet worker should carry both rule tails: %q", in)
	}

	// 逆向:含逆向红线尾,且逆向优先于内网(不渲染内网尾)。变体正文
	//(逆向期纪律段)来自 DB 种子,此处仅断言代码固定部分——与 intranet 用例同口径。
	rev := workerSystem("", "", "/data", "/data", true, true)
	if !strings.Contains(rev, "反 AI 蜜罐红线") || !strings.Contains(rev, "逆向红线") ||
		strings.Contains(rev, "内网红线") {
		t.Fatalf("reverse worker should carry anti-trap + reverse rules, not intranet tail")
	}

	// DB 覆盖正文(含 intranet/reverse 变体)也删不掉红线段。
	PromptOverride = func(k string) (string, bool) { return "用户编辑正文", true }
	if got := workerSystem("", "", "/data", "/data", false, false); !strings.Contains(got, "反 AI 蜜罐红线") {
		t.Fatalf("edited body must not drop anti-trap rules: %q", got)
	}
	if got := workerSystem("", "", "/data", "/data", true, false); !strings.Contains(got, "反 AI 蜜罐红线") || !strings.Contains(got, "内网红线") {
		t.Fatalf("edited intranet body must not drop either rule tail: %q", got)
	}
	if got := workerSystem("", "", "/data", "/data", false, true); !strings.Contains(got, "逆向红线") {
		t.Fatalf("edited reverse body must not drop reverse rule tail: %q", got)
	}
}
