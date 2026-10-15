package server

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"modernc.org/sqlite"
)

func TestJudgeConfigRejectsInvalidRetryBeforeSaving(t *testing.T) {
	// No manager is needed: invalid input must be rejected before database writes.
	s := &Server{}
	for _, fields := range []string{
		`"retry_count":-1`, `"retry_count":21`, `"retry_count":1.5`,
		`"retry_interval_ms":-1`, `"retry_interval_ms":3600001`, `"retry_interval_ms":1.5`,
	} {
		t.Run(fields, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/intercept/judge", strings.NewReader(`{"fail_action":"allow","ask_timeout_action":"deny",`+fields+`}`))
			w := httptest.NewRecorder()
			s.interceptSetJudgeConfig(w, req)
			if w.Code != 400 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

var judgeConfigSQLiteNow sync.Once

func TestJudgeConfigRetryRoundTrip(t *testing.T) {
	// Exercise production settings SQL without requiring an external PG service.
	judgeConfigSQLiteNow.Do(func() {
		sqlite.MustRegisterDeterministicScalarFunction("now", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
			return "2026-01-01 00:00:00", nil
		})
	})
	sqldb, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if _, err := sqldb.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	pg := &db.DB{DB: sqldb}
	s := &Server{m: &Manager{pg: pg, interceptor: intercept.New(pg)}}
	for _, tc := range []struct{ count, interval int }{{2, 17}, {20, 3600000}, {0, 0}} {
		cfg := s.m.interceptor.GetJudgeConfig()
		cfg.RetryCount, cfg.RetryIntervalMS = tc.count, tc.interval
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		s.interceptSetJudgeConfig(w, httptest.NewRequest("PUT", "/api/intercept/judge", strings.NewReader(string(body))))
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		// Construct a fresh interceptor to prove persistence, rather than cache reuse.
		s.m.interceptor = intercept.New(pg)
		w = httptest.NewRecorder()
		s.interceptGetJudgeConfig(w, httptest.NewRequest("GET", "/api/intercept/judge", nil))
		var got intercept.JudgeConfig
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.RetryCount != tc.count || got.RetryIntervalMS != tc.interval {
			t.Fatalf("saved=%+v got=%+v", cfg, got)
		}
	}
}
