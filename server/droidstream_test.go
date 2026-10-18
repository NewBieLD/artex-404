package server

// droidstream_test.go:期 2 传输层端到端(与 droidgateway_test.go 同款 PG-gated
// skip 模式)。用 gorilla 客户端模拟 DroidBridge APK 的帧行为,验证:
//   - pull:data 帧流式分片(乱序拒绝)边收边写 + result 聚合
//   - push:分片推送只有 done 片有应答
//   - 隧道:tcp_open/tcp_opened、tcp_send/tcp_data 双向、tcp_close/tcp_closed

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/gorilla/websocket"
)

// streamDeviceEnv 起 store+网关+监听并登记一台假设备,拨好 WS。
func streamDeviceEnv(t *testing.T) (*DeviceGateway, *websocket.Conn, chan map[string]any, string, func()) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	store := db.NewDeviceStore(pg, []byte("test-jwt-key-material-32bytes!!!"))
	// 唯一命名:测试被强杀时残留的绑定不会让下一次 hello 撞 4005。
	devID := fmt.Sprintf("dev-stream-%d", time.Now().UnixNano())
	rec, token, err := store.Enroll(context.Background(), "gw-stream-e2e-"+devID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	g := newDeviceGateway(store)
	if err := g.Listen("127.0.0.1", 0); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	_, port, _ := g.ListenInfo()
	ws, frames := dialDevice(t, "ws://127.0.0.1:"+itoa(port)+"/ws/droid?token="+token)
	wsSend(t, ws, map[string]any{"t": "hello", "deviceId": devID, "model": "fake", "androidVersion": "14", "sdkInt": 34, "rooted": true})
	if f := waitFrame(t, frames, "welcome"); f["deviceId"] != devID {
		t.Fatalf("welcome deviceId 意外: %v", f)
	}
	cleanup := func() {
		_ = ws.Close()
		g.Close()
		_ = store.Delete(context.Background(), rec.ID)
		pg.Close()
	}
	return g, ws, frames, devID, cleanup
}

func itoa(v int) string {
	return json.Number(jsonInt(v)).String()
}

func jsonInt(v int) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// deviceReplyStream 把 data 分片 + result 按序发回(模拟 APK 对 pull 的应答)。
func deviceReplyStream(t *testing.T, ws *websocket.Conn, reqID string, payload []byte) {
	t.Helper()
	chunk := 7 // 故意切非对齐小块,验证拼装
	for i := 0; i*chunk < len(payload) || i == 0; i++ {
		end := (i + 1) * chunk
		if end > len(payload) {
			end = len(payload)
		}
		last := end >= len(payload)
		wsSend(t, ws, map[string]any{
			"t": "data", "reqId": reqID, "seq": i,
			"b64": base64.StdEncoding.EncodeToString(payload[i*chunk : end]),
			"done": last,
		})
		if last {
			break
		}
	}
	wsSend(t, ws, map[string]any{"t": "result", "reqId": reqID, "ok": true})
}

func TestDeviceGatewayPullStream(t *testing.T) {
	g, ws, frames, devID, cleanup := streamDeviceEnv(t)
	defer cleanup()

	payload := []byte("dex-magic-0123456789-abcdefghij-流式拼装校验")
	var buf bytes.Buffer
	done := make(chan struct{})
	var pullErr error
	go func() {
		defer close(done)
		_, _, pullErr = g.PullFile(devID, "/data/local/tmp/fake.tar", 1<<20, &buf, 10*time.Second)
	}()
	// 设备侧:等 pull 帧,回 data 分片 + result。
	f := waitFrame(t, frames, "pull")
	if f["path"] != "/data/local/tmp/fake.tar" {
		t.Fatalf("pull path 意外: %v", f)
	}
	deviceReplyStream(t, ws, f["reqId"].(string), payload)
	<-done
	if pullErr != nil {
		t.Fatalf("PullFile: %v", pullErr)
	}
	if !bytes.Equal(buf.Bytes(), payload) {
		t.Fatalf("流式拼装结果不一致: %q", buf.String())
	}
}

func TestDeviceGatewayPushFile(t *testing.T) {
	g, ws, frames, devID, cleanup := streamDeviceEnv(t)
	defer cleanup()

	payload := bytes.Repeat([]byte("frida-server-bytes"), 200_000) // ~3.4MB,跨多片
	resCh := make(chan deviceResult, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := g.PushFile(devID, "/data/local/tmp/frida-server", payload, "0755", 60*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		resCh <- res
	}()
	var got [][]byte
	var lastFrame map[string]any
	for {
		f := waitFrame(t, frames, "push")
		lastFrame = f
		raw, _ := base64.StdEncoding.DecodeString(f["b64"].(string))
		got = append(got, raw)
		if done, _ := f["done"].(bool); done {
			break
		}
	}
	if lastFrame["path"] != "/data/local/tmp/frida-server" || lastFrame["mode"] != "0755" {
		t.Fatalf("push 帧字段意外: %v", lastFrame)
	}
	// 只有 done 片应答:设备回一个 result。
	wsSend(t, ws, map[string]any{"t": "result", "reqId": lastFrame["reqId"], "ok": true})
	select {
	case res := <-resCh:
		if !res.OK {
			t.Fatalf("push 结果失败: %+v", res)
		}
	case err := <-errCh:
		t.Fatalf("PushFile: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("PushFile 未在应答后返回")
	}
	var assembled []byte
	for _, c := range got {
		assembled = append(assembled, c...)
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatalf("分片拼装不一致(%d vs %d 字节)", len(assembled), len(payload))
	}
}

func TestDeviceGatewayTunnel(t *testing.T) {
	g, ws, frames, devID, cleanup := streamDeviceEnv(t)
	defer cleanup()

	port, err := g.OpenTunnel(devID, "127.0.0.1", 27042)
	if err != nil {
		t.Fatalf("OpenTunnel: %v", err)
	}
	// 复用:同目标再开拿到同一端口。
	port2, _ := g.OpenTunnel(devID, "127.0.0.1", 27042)
	if port2 != port {
		t.Fatalf("同目标隧道未复用: %d vs %d", port2, port)
	}

	echo := make(chan []byte, 1)
	go func() {
		conn, derr := net.Dial("tcp", "127.0.0.1:"+jsonInt(port))
		if derr != nil {
			close(echo)
			return
		}
		_, _ = conn.Write([]byte("frida-hello"))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		echo <- buf[:n]
		_ = conn.Close()
	}()
	// 设备侧:应答 tcp_opened,把 tcp_send 原样回成 tcp_data(模拟 frida-server 回显)。
	open := waitFrame(t, frames, "tcp_open")
	if open["host"] != "127.0.0.1" || jsonInt(int(open["port"].(float64))) != "27042" {
		t.Fatalf("tcp_open 目标意外: %v", open)
	}
	wsSend(t, ws, map[string]any{"t": "tcp_opened", "reqId": open["reqId"],
		"tunnelId": open["tunnelId"], "connId": open["connId"], "ok": true})
	sent := waitFrame(t, frames, "tcp_send")
	wsSend(t, ws, map[string]any{"t": "tcp_data", "tunnelId": open["tunnelId"], "connId": open["connId"],
		"b64": sent["b64"]})
	// 客户端收完断开 → 网关发 tcp_close;设备补 tcp_closed 结束。
	got, ok := <-echo
	if !ok {
		t.Fatalf("隧道客户端拨号失败")
	}
	if string(got) != "frida-hello" {
		t.Fatalf("隧道回显不一致: %q", got)
	}
	waitFrame(t, frames, "tcp_close")
	wsSend(t, ws, map[string]any{"t": "tcp_closed", "tunnelId": open["tunnelId"], "connId": open["connId"]})
}
