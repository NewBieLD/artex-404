package report

import (
	"strings"
	"testing"
)

func TestDebugTransform(t *testing.T) {
	ev := "【最小可复现请求与关键回显】\n\n1) 未授权枚举：\n$ curl -sk -X POST -H 'Content-Type: application/json' \\\n  -d '{\"a\":1}' \\\n  https://x.example.com/api\n→ HTTP 200 {\"code\":\"0\"}\n\n2) 说明文字"
	lines := strings.Split(ev, "\n")
	for idx, line := range lines {
		t.Logf("line[%d]=%q", idx, line)
	}
	trimmed := strings.TrimSpace(lines[3])
	trimmed = strings.TrimPrefix(trimmed, "$")
	trimmed = strings.TrimSpace(trimmed)
	t.Logf("trimmed=%q hasCurlPrefix=%v", trimmed, strings.HasPrefix(trimmed, "curl "))
	j := 3
	for j+1 < len(lines) && strings.HasSuffix(lines[j], "\\") {
		j++
		t.Logf("cont lines[%d]=%q", j, lines[j])
	}
	t.Logf("final j=%d", j)
}
