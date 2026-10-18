// droidgateway.go 是 DroidBridge 反连 WS 网关,协议与哨兵
// DroidGateway(packages/web/src/droid-gateway.ts)逐帧对齐:设备拨
// ws(s)://host:port/ws/droid?token=…,hello 优先(hb 抢跑 4001 关闭),
// 心跳 15s,45s 无帧判「无响应」(看门狗 5s sweep),同 deviceId 新连接
// 替换旧连接(4003)。判活闭环(hello/welcome + hb + result)在期 1 落地;
// 期 2 传输层(data 帧流式 pull/push 分片/TCP 隧道)见 droidstream.go。
//
// 一个要害照搬哨兵的教训:静默 ≠ 断开。Android(尤其模拟器)能把整个 app
// SIGSTOP——socket 还是 ESTABLISHED,但任何代码都不再执行,心跳停、请求
// 永不回答。所以看门狗按「最后任意帧」计时,无响应的设备立即 fail 它的
// pending 调用,恢复的第一帧自动清除标记(解冻后同 socket 直接可用)。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/gorilla/websocket"
)

// 判活参数(PROGRESS.md 既定 15s/45s/5s):与 APK 心跳周期、哨兵网关一致。
const (
	deviceHeartbeatHint = 15 * time.Second // welcome 里告知设备的心跳周期(仅提示,APK 自身写死 15s)
	deviceStaleAfter    = 45 * time.Second // 静默超过此时长判「无响应」
	deviceWatchdogTick  = 5 * time.Second  // 看门狗巡检周期
	// WS 关闭码(应用层自定义段,与哨兵网关同值):4001 需先握手、4002 缺
	// deviceId、4003 被新连接替换、4004 登记已删除、4005 token 已绑定其它设备。
	deviceCloseHandshake = 4001
	deviceCloseNoDevID   = 4002
	deviceCloseReplaced  = 4003
	deviceCloseDeleted   = 4004
	deviceCloseBound     = 4005
)

// deviceResult 是一次请求(exec 等)的聚合应答。Bytes 仅内部使用(无 onData
// 的流式 pull 在 result 帧时拼装),不进任何 JSON 序列化路径。
type deviceResult struct {
	OK     bool   `json:"ok"`
	Code   int    `json:"code,omitempty"`
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Error  string `json:"error,omitempty"`
	Bytes  []byte `json:"-"`
}

// deviceConn 是一台在线设备的活连接。
type deviceConn struct {
	ws        *websocket.Conn
	writeMu   sync.Mutex // gorilla 一条 conn 只允许一个并发 writer
	dbID      int64      // devices 行 id(token 鉴权时定)
	deviceID  string
	lastFrame time.Time
	stale     bool // 看门狗置位;恢复的第一帧清除
}

// DeviceGateway 持有全部在线设备连接;工具/REST 经它发请求帧并等 result。
type DeviceGateway struct {
	store *db.DeviceStore

	mu      sync.Mutex
	conns   map[string]*deviceConn // deviceId → live conn
	pendMu  sync.Mutex
	pending map[string]*gwPending     // reqId → 等待者
	pendDev map[string]string         // reqId → deviceId(断连时精确 fail)
	streams map[string]*gwStream      // reqId → 流式聚积(data 帧,见 droidstream.go)
	tunMu   sync.Mutex                // 隧道注册表锁
	tunnels map[string]*gwTunnel      // deviceID|host:port → 隧道(frida -H 用)

	listener   *http.Server // 独立反连监听(不过门控/JWT;鉴权=token)
	listenAddr string
	listenPort int

	watchdogStop chan struct{}
	watchdogOn   atomic.Bool

	counter atomic.Int64
}

func newDeviceGateway(store *db.DeviceStore) *DeviceGateway {
	return &DeviceGateway{store: store, conns: map[string]*deviceConn{},
		pending: map[string]*gwPending{}, pendDev: map[string]string{},
		streams: map[string]*gwStream{}, tunnels: map[string]*gwTunnel{}}
}

// --- 监听生命周期 ---

// Listen 起/重起独立反连监听(sentine 同款运行时可重绑:操作者在设备页挑
// 网卡)。端口登记平台台账,端口审计不误报。
func (g *DeviceGateway) Listen(host string, port int) error {
	if net.ParseIP(host) == nil {
		return fmt.Errorf("监听地址非法(需 IP): %s", host)
	}
	// port=0 允许(内核随机分配,测试用);REST 层自行兜默认端口。
	if port < 0 || port > 65535 {
		return fmt.Errorf("端口非法: %d", port)
	}
	g.StopListener()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/droid", g.serveWS)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconvItoa(port)))
	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}
	g.listener = srv
	g.listenAddr = host
	g.listenPort = ln.Addr().(*net.TCPAddr).Port
	registerManagedPort(g.listenPort)
	log.Printf("[devices] 反连监听: %s", g.listenHostPort())
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[devices] 反连监听退出: %v", err)
			g.mu.Lock()
			if g.listener == srv {
				g.listener = nil
			}
			g.mu.Unlock()
		}
	}()
	return nil
}

// StopListener 停独立监听(已停幂等)。
func (g *DeviceGateway) StopListener() {
	g.mu.Lock()
	srv := g.listener
	g.listener = nil
	g.mu.Unlock()
	if srv != nil {
		unregisterManagedPort(g.listenPort)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
}

// ListenInfo 返回当前监听(host, port, 是否在听)。
func (g *DeviceGateway) ListenInfo() (string, int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.listener == nil {
		return "", 0, false
	}
	return g.listenAddr, g.listenPort, true
}

func (g *DeviceGateway) listenHostPort() string {
	if g.listener == nil {
		return ""
	}
	return net.JoinHostPort(g.listenAddr, strconvItoa(g.listenPort))
}

// Close 收尾:停监听 + 踢掉全部设备。
func (g *DeviceGateway) Close() {
	g.StopListener()
	g.mu.Lock()
	conns := make([]*deviceConn, 0, len(g.conns))
	for _, c := range g.conns {
		conns = append(conns, c)
	}
	g.mu.Unlock()
	for _, c := range conns {
		g.closeConn(c, 1000, "server shutdown")
	}
}

func strconvItoa(v int) string {
	return fmt.Sprintf("%d", v)
}

// serveWS 是设备升级入口:只认 /ws/droid + 有效 token,双查过才升级。
func (g *DeviceGateway) serveWS(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Error(w, "token required", http.StatusUnauthorized)
		return
	}
	rec, err := g.store.FindByToken(r.Context(), token)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if rec == nil {
		log.Printf("[devices] 反连被拒绝:token 无效或已删除(remote=%s)", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true },
		ReadBufferSize: 32 * 1024, WriteBufferSize: 32 * 1024}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade 已写过 400
	}
	g.onConnection(ws, rec)
}

// onConnection 驱动一条设备连接的整个生命周期:hello 优先、任意帧判活、
// 断开精确注销(被替换的旧连接不得注销它的继任者)。
func (g *DeviceGateway) onConnection(ws *websocket.Conn, rec *db.DeviceRecord) {
	var conn *deviceConn
	helloed := false
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			g.onClose(conn)
			return
		}
		var frame struct {
			T          string `json:"t"`
			DeviceID   string `json:"deviceId"`
			Model      string `json:"model"`
			AndroidVer string `json:"androidVersion"`
			SdkInt     int    `json:"sdkInt"`
			Rooted     bool   `json:"rooted"`
			ReqID      string `json:"reqId"`
			OK         bool   `json:"ok"`
			Code       int    `json:"code"`
			Stdout     string `json:"stdout"`
			Stderr     string `json:"stderr"`
			Err        string `json:"error"`
			Seq        int    `json:"seq"`
			B64        string `json:"b64"`
			Done       bool   `json:"done"`
			TunnelID   string `json:"tunnelId"`
			ConnID     string `json:"connId"`
		}
		if json.Unmarshal(raw, &frame) != nil {
			continue // 非 JSON 帧丢弃(哨兵同款:不杀连接)
		}
		if conn != nil {
			g.markAlive(conn)
		}
		if !helloed {
			if frame.T != "hello" {
				g.closeConnRaw(ws, deviceCloseHandshake, "handshake required")
				return
			}
			if frame.DeviceID == "" {
				g.closeConnRaw(ws, deviceCloseNoDevID, "deviceId required")
				return
			}
			// token→deviceId 绑定(首连),冲突即拒绝:一台设备一个 token。
			bctx, bcancel := context.WithTimeout(context.Background(), 5*time.Second)
			berr := g.store.BindOnHello(bctx, rec.ID, frame.DeviceID,
				orDefault(frame.Model, "未知机型"), orDefault(frame.AndroidVer, "未知"),
				frame.SdkInt, frame.Rooted)
			bcancel()
			if berr != nil {
				log.Printf("[devices] hello 绑定失败: %v", berr)
				g.closeConnRaw(ws, deviceCloseBound, berr.Error())
				return
			}
			// 同 deviceId 新连接胜出:旧 socket 半死的先例见哨兵注释。
			g.mu.Lock()
			if prev := g.conns[frame.DeviceID]; prev != nil {
				g.mu.Unlock()
				g.closeConn(prev, deviceCloseReplaced, "replaced by a new connection")
				g.mu.Lock()
			}
			conn = &deviceConn{ws: ws, dbID: rec.ID, deviceID: frame.DeviceID, lastFrame: time.Now()}
			g.conns[frame.DeviceID] = conn
			g.mu.Unlock()
			g.ensureWatchdog()
			helloed = true
			if g.sendJSON(conn, map[string]any{"t": "welcome", "deviceId": frame.DeviceID,
				"heartbeatMs": deviceHeartbeatHint.Milliseconds()}) != nil {
				return
			}
			log.Printf("[devices] 设备上线:#%d %s(%s,Android %s,rooted=%v,remote=%s)",
				rec.ID, frame.DeviceID, orDefault(frame.Model, "未知机型"),
				orDefault(frame.AndroidVer, "未知"), frame.Rooted, ws.RemoteAddr())
			continue
		}
		switch frame.T {
		case "hb":
			go g.touchSeen(conn)
		case "result":
			res := deviceResult{OK: frame.OK, Code: frame.Code,
				Stdout: frame.Stdout, Stderr: frame.Stderr, Error: frame.Err}
			g.assembleStream(frame.ReqID, &res)
			g.resolveResult(frame.ReqID, res)
		case "data":
			g.handleDataFrame(frame.ReqID, frame.Seq, frame.B64)
		case "tcp_opened", "tcp_data", "tcp_closed":
			g.handleTcpDeviceFrame(frame.T, frame.TunnelID, frame.ConnID, frame.ReqID, frame.B64, frame.OK, frame.Err)
		default:
			// 未知帧:markAlive 已计,忽略载荷。
		}
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func (g *DeviceGateway) touchSeen(c *deviceConn) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := g.store.TouchSeen(ctx, c.dbID); err != nil {
		log.Printf("[devices] 心跳落库失败(#%d): %v", c.dbID, err)
	}
}

// onClose 断开清理:仅当这条连接仍是该 deviceId 的现行连接才注销
// (被 4003 替换的旧连接晚到关闭,不得清掉继任者)。
func (g *DeviceGateway) onClose(c *deviceConn) {
	if c == nil {
		return
	}
	g.mu.Lock()
	current := g.conns[c.deviceID]
	if current == c {
		delete(g.conns, c.deviceID)
	}
	g.mu.Unlock()
	if current != c {
		return
	}
	g.stopWatchdogIfIdle()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := g.store.SetStatus(ctx, c.dbID, db.DeviceOffline); err != nil {
		log.Printf("[devices] 离线落库失败(#%d): %v", c.dbID, err)
	}
	g.failPendingOf(c.deviceID, "设备连接已断开")
	g.closeTunnelsOf(c.deviceID)
	log.Printf("[devices] 设备离线:#%d %s", c.dbID, c.deviceID)
}

// --- 看门狗 ---

func (g *DeviceGateway) ensureWatchdog() {
	if g.watchdogOn.Load() {
		return
	}
	g.mu.Lock()
	if g.watchdogOn.Swap(true) {
		g.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	g.watchdogStop = stop
	g.mu.Unlock()
	go func() {
		ticker := time.NewTicker(deviceWatchdogTick)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				g.sweepLiveness()
			}
		}
	}()
}

func (g *DeviceGateway) stopWatchdogIfIdle() {
	g.mu.Lock()
	if len(g.conns) > 0 || !g.watchdogOn.Load() {
		g.mu.Unlock()
		return
	}
	stop := g.watchdogStop
	g.watchdogStop = nil
	g.watchdogOn.Store(false)
	g.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

// sweepLiveness 巡检:静默超阈 → 置 stale、立即 fail 该设备 pending。
func (g *DeviceGateway) sweepLiveness() {
	now := time.Now()
	g.mu.Lock()
	var stale []*deviceConn
	for _, c := range g.conns {
		if !c.stale && now.Sub(c.lastFrame) > deviceStaleAfter {
			c.stale = true
			stale = append(stale, c)
		}
	}
	g.mu.Unlock()
	for _, c := range stale {
		idle := now.Sub(c.lastFrame).Round(time.Second)
		log.Printf("[devices] 设备无响应:#%d %s(已 %s 未收到心跳,进程可能被冻结或停止响应)",
			c.dbID, c.deviceID, idle)
		g.failPendingOf(c.deviceID, fmt.Sprintf(
			"设备无响应:已 %s 未收到心跳(DroidBridge 进程可能被系统或模拟器冻结:socket 还在,但 app 不再执行任何代码)",
			idle))
	}
}

// markAlive 任意帧到达:刷新计时;冻结恢复的第一帧清除 stale 标记。
func (g *DeviceGateway) markAlive(c *deviceConn) {
	g.mu.Lock()
	current := g.conns[c.deviceID]
	if current != c { // 被替换的旧连接不得刷新继任者的活度
		g.mu.Unlock()
		return
	}
	c.lastFrame = time.Now()
	wasStale := c.stale
	c.stale = false
	g.mu.Unlock()
	if wasStale {
		log.Printf("[devices] 设备恢复响应:#%d %s", c.dbID, c.deviceID)
	}
}

// Liveness 运行态判活查询(REST/工具用):在线返回 idle 秒数与是否无响应。
func (g *DeviceGateway) Liveness(deviceID string) (idle time.Duration, stale bool, online bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.conns[deviceID]
	if c == nil {
		return 0, false, false
	}
	idle = time.Since(c.lastFrame)
	return idle, c.stale || idle > deviceStaleAfter, true
}

// OnlineDeviceIDs 当前在线的 deviceId 集合(判定 DB status 与运行态合流)。
func (g *DeviceGateway) OnlineDeviceIDs() map[string]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]bool, len(g.conns))
	for id := range g.conns {
		out[id] = true
	}
	return out
}

// Disconnect 踢一台设备(删除登记时用)。
func (g *DeviceGateway) Disconnect(deviceID string) {
	g.mu.Lock()
	c := g.conns[deviceID]
	g.mu.Unlock()
	if c != nil {
		g.closeConn(c, deviceCloseDeleted, "deleted")
	}
}

func (g *DeviceGateway) closeConn(c *deviceConn, code int, reason string) {
	c.writeMu.Lock()
	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason), time.Now().Add(2*time.Second))
	c.writeMu.Unlock()
	_ = c.ws.Close()
}

func (g *DeviceGateway) closeConnRaw(ws *websocket.Conn, code int, reason string) {
	_ = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason), time.Now().Add(2*time.Second))
	_ = ws.Close()
}

// --- 请求往返(期 1:probe_device 的 exec;期 2:pull/push/隧道见 droidstream.go)---

// Request 给设备发一帧请求并等它的 result;deviceID 离线/无响应立即失败,
// 不等自己的超时。frame 需带 t 字段,reqId 由这里注入。
func (g *DeviceGateway) Request(deviceID string, frame map[string]any, timeout time.Duration) (deviceResult, error) {
	return g.requestInternal(deviceID, frame, timeout, nil)
}

func (g *DeviceGateway) sendJSON(c *deviceConn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	err = c.ws.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()
	return err
}

func (g *DeviceGateway) resolveResult(reqID string, res deviceResult) {
	g.pendMu.Lock()
	p := g.pending[reqID]
	if p != nil {
		delete(g.pending, reqID)
		delete(g.pendDev, reqID)
	}
	g.pendMu.Unlock()
	if p != nil {
		p.ch <- res
	}
}

func (g *DeviceGateway) dropPending(reqID string) {
	g.pendMu.Lock()
	delete(g.pending, reqID)
	delete(g.pendDev, reqID)
	delete(g.streams, reqID)
	g.pendMu.Unlock()
}

func (g *DeviceGateway) failPendingOf(deviceID, reason string) {
	g.pendMu.Lock()
	var pending []*gwPending
	for id, dev := range g.pendDev {
		if dev != deviceID {
			continue
		}
		if p := g.pending[id]; p != nil {
			pending = append(pending, p)
		}
		delete(g.pending, id)
		delete(g.pendDev, id)
		delete(g.streams, id)
	}
	g.pendMu.Unlock()
	for _, p := range pending {
		p.ch <- deviceResult{OK: false, Error: reason}
	}
}
