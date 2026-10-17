package report

import "testing"

func TestCurlToRaw(t *testing.T) {
	cmd := `curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"url":"/artemis/api/resource/v2/camera/search","method":"POST","data":{"pageNo":1,"pageSize":10}}' \
  https://218.206.148.230/api/transit/api`
	raw, ok := curlToRaw(cmd)
	if !ok {
		t.Fatal("not ok")
	}
	t.Log("\n" + raw)
	for _, want := range []string{
		"POST /api/transit/api HTTP/1.1",
		"Host: 218.206.148.230",
		"Content-Type: application/json",
		"Content-Length:",
		`"pageNo":1`,
	} {
		if !contains(raw, want) {
			t.Fatalf("missing %q in:\n%s", want, raw)
		}
	}
}

func TestTransformCurlEvidence(t *testing.T) {
	ev := "【最小可复现请求与关键回显】\n\n1) 未授权枚举：\n$ curl -sk -X POST -H 'Content-Type: application/json' \\\n  -d '{\"a\":1}' \\\n  https://x.example.com/api\n→ HTTP 200 {\"code\":\"0\"}\n\n2) 说明文字"
	out := transformCurlEvidence(ev)
	t.Log("\n" + out)
	for _, bad := range []string{"curl "} {
		if contains(out, bad) {
			t.Fatalf("curl 残留: %s", out)
		}
	}
	for _, want := range []string{"POST /api HTTP/1.1", "Host: x.example.com", "回包：", "说明文字"} {
		if !contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
