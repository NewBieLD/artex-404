package report

import "testing"

func TestDebugSplit(t *testing.T) {
	cmd := `curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"url":"/x"}' \
  https://x.example.com/api`
	t.Logf("cmd bytes tail: %q", cmd[len(cmd)-60:])
	toks := splitCurlArgs(cmd)
	for i, tk := range toks {
		t.Logf("tok[%d]=%q", i, tk)
	}
}
