package server

// droidgateway_test.go:反连网关端到端测试(现有 PG-gated skip 模式)。
// 用 gorilla 客户端模拟 DroidBridge:hello→welcome、hb、exec 往返、
// 坏 token 401、hb 抢跑 4001、看门狗 stale 判定与 pending 立即失败。

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/gorilla/websocket"
)

// dialDevice 拨一条设备连接,返回 ws 与读帧通道。
func dialDevice(t *testing.T, url string) (*websocket.Conn, chan map[string]any) {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	frames := make(chan map[string]any, 8)
	go func() {
		defer close(frames)
		for {
			_, raw, err := ws.ReadMessage()
			if err != nil {
				return
			}
			var f map[string]any
			if json.Unmarshal(raw, &f) == nil {
				frames <- f
			}
		}
	}()
	return ws, frames
}

func waitFrame(t *testing.T, frames chan map[string]any, want string) map[string]any {
	t.Helper()
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatalf("连接已关,等不到 %s 帧", want)
			}
			if f["t"] == want {
				return f
			} // 其它帧(如无)继续等
		case <-time.After(5 * time.Second):
			t.Fatalf("等 %s 帧超时", want)
		}
	}
}

func wsSend(t *testing.T, ws *websocket.Conn, v map[string]any) {
	t.Helper()
	if err := ws.WriteJSON(v); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestDeviceGatewayLifecycle(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()
	ctx := context.Background()
	store := db.NewDeviceStore(pg, []byte("test-jwt-key-material-32bytes!!!"))
	rec, token, err := store.Enroll(ctx, "gw-e2e")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// 注意必须 defer 而非 t.Cleanup:本测试体的 defer pg.Close() 先于任何
	// t.Cleanup 执行,Cleanup 里的删除会撞上已关闭的连接池。
	defer func() { _ = store.Delete(context.Background(), rec.ID) }()

	g := newDeviceGateway(store)
	defer g.Close()
	if err := g.Listen("127.0.0.1", 0); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	_, port, ok := g.ListenInfo()
	if !ok {
		t.Fatal("监听未就绪")
	}
	base := "ws://127.0.0.1:" + strconv.Itoa(port) + "/ws/droid"

	// 1) 坏 token:升级被拒(HTTP 401)。
	if _, _, err := websocket.DefaultDialer.Dial(base+"?token=badtoken", nil); err == nil {
		t.Fatal("坏 token 不应升级成功")
	}

	// 2) hb 抢在 hello 前:应用层 4001 关闭。
	wsPre, framesPre := dialDevice(t, base+"?token="+token)
	defer wsPre.Close()
	wsSend(t, wsPre, map[string]any{"t": "hb"})
	select {
	case _, ok := <-framesPre:
		if ok {
			t.Fatal("hb 抢跑不应收到任何业务帧")
		} // 通道关闭 = 连接被关,符合预期
	case <-time.After(5 * time.Second):
		t.Fatal("hb 抢跑后连接应被关闭")
	}

	// 3) 正常握手:hello → welcome(deviceId 回显)。deviceId 每次唯一,
	// 历史残留(崩溃跑剩的行)不会撞唯一索引。
	ws, frames := dialDevice(t, base+"?token="+token)
	defer ws.Close()
	devID := "gw-e2e-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	wsSend(t, ws, map[string]any{"t": "hello", "token": token, "deviceId": devID,
		"model": "OnePlus 9", "androidVersion": "14", "sdkInt": 34, "rooted": true})
	welcome := waitFrame(t, frames, "welcome")
	if welcome["deviceId"] != devID {
		t.Fatalf("welcome deviceId = %v", welcome["deviceId"])
	}

	// DB 侧:绑定 + online。
	got, _ := store.Get(ctx, rec.ID)
	if got == nil || got.DeviceID != devID || got.Status != db.DeviceOnline {
		t.Fatalf("hello 后 DB 行 = %+v", got)
	}

	// 4) exec 往返:客户端只应答 cmd=id 的 exec(后面的 sleep 探测要故意挂起)。
	go func() {
		for f := range frames {
			if f["t"] == "exec" && f["cmd"] == "id" {
				wsSend(t, ws, map[string]any{"t": "result", "reqId": f["reqId"],
					"ok": true, "code": 0, "stdout": "uid=10234(u0_a234)"})
			}
		}
	}()
	res, rerr := g.Request(devID, map[string]any{"t": "exec", "cmd": "id", "asRoot": false}, 5*time.Second)
	if rerr != nil || !res.OK || res.Stdout != "uid=10234(u0_a234)" {
		t.Fatalf("Request: %+v %v", res, rerr)
	}

	// 5) 心跳 + 同步往返锚定:hb 后再做一次 exec 往返,Request 返回即 result
	// 帧已处理,而同连接帧按序处理 ⇒ hb 必然已消费,后续拨表不会被冲掉。
	wsSend(t, ws, map[string]any{"t": "hb"})
	if _, err := g.Request(devID, map[string]any{"t": "exec", "cmd": "id", "asRoot": false}, 5*time.Second); err != nil {
		t.Fatalf("锚定往返失败: %v", err)
	}

	// 6a) 入口拦截:静默已超阈值时,新 Request 直接拒绝,不发帧。
	g.mu.Lock()
	if c := g.conns[devID]; c != nil {
		c.lastFrame = time.Now().Add(-deviceStaleAfter - time.Second)
	}
	g.mu.Unlock()
	if _, err := g.Request(devID, map[string]any{"t": "exec", "cmd": "id"}, time.Second); err == nil ||
		!strings.Contains(err.Error(), "无响应") {
		t.Fatalf("静默设备的直接请求应被入口拒绝: %v", err)
	}

	// 6b) 看门狗:拨到阈值内一点点,让 Request 挂上 pending(客户端不回包),
	// 随时间越过阈值,sweep 判无响应并立即失败化挂起请求。
	g.mu.Lock()
	if c := g.conns[devID]; c != nil {
		c.lastFrame = time.Now().Add(-deviceStaleAfter + 500*time.Millisecond)
	}
	g.mu.Unlock()
	pendDone := make(chan deviceResult, 1)
	errDone := make(chan error, 1)
	go func() {
		res, err := g.Request(devID, map[string]any{"t": "exec", "cmd": "sleep"}, 30*time.Second)
		pendDone <- res
		errDone <- err
	}()
	time.Sleep(1200 * time.Millisecond) // 让静默时长越过阈值
	g.sweepLiveness()
	if _, stale, _ := g.Liveness(devID); !stale {
		t.Fatal("静默超阈值后应判 stale")
	}
	select {
	case res := <-pendDone:
		// 失败化有两形:入口/看门狗返回 err,或 res.OK=false+Error(通道解析形)。
		if res.OK && res.Error == "" {
			t.Fatal("stale 设备的挂起请求应失败")
		}
		if !strings.Contains(res.Error, "无响应") {
			t.Fatalf("失败原因应指明无响应: %q", res.Error)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("挂起请求未被看门狗失败化")
	}
	select {
	case <-errDone:
	default:
	}

	// 7) 恢复的第一帧清除 stale(hb 异步处理,轮询等待回落)。
	wsSend(t, ws, map[string]any{"t": "hb"})
	recoverDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(recoverDeadline) {
		if _, stale, _ := g.Liveness(devID); !stale {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, stale, _ := g.Liveness(devID); stale {
		t.Fatal("恢复帧后 stale 应回落")
	}

	// 8) 断开:DB 标 offline,离线设备 Request 立即失败。onClose 先摘连接表、
	// 后异步落库,所以轮询 DB 直到 offline 而不是读一次。
	_ = ws.Close()
	offlineDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(offlineDeadline) {
		got, _ = store.Get(ctx, rec.ID)
		if got != nil && got.Status == db.DeviceOffline {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, _, online := g.Liveness(devID); online {
		t.Fatal("断开后应离线")
	}
	if _, err := g.Request(devID, map[string]any{"t": "exec", "cmd": "id"}, time.Second); err == nil {
		t.Fatal("离线设备 Request 应失败")
	}
	got, _ = store.Get(ctx, rec.ID)
	if got == nil || got.Status != db.DeviceOffline {
		t.Fatalf("断开后 DB 行 = %+v", got)
	}
}
