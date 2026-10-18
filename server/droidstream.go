// droidstream.go 是反连网关的期 2 传输层:data 帧路由(流式 pull 聚积)、
// pushFile 分片推送、TCP 隧道(本机监听 ↔ 设备端口,frida -H 用)。帧格式与
// 哨兵 droid-protocol.ts 逐字段对齐,DroidBridge APK 无需改动即可互通:
//
//   pull   {t,reqId,path,maxBytes}            → data*(seq,b64,done) + result
//   push   {t,reqId,path,seq,done,b64,mode?}  → result(仅 done 块应答)
//   tcp_open  {t,reqId,tunnelId,connId,host,port} → tcp_opened{ok}
//   tcp_send  {t,tunnelId,connId,b64}         (server→device)
//   tcp_data  {t,tunnelId,connId,b64}         (device→server)
//   tcp_close {t,tunnelId,connId}             / tcp_closed(device→server)
//
// 上限沿用哨兵常量:单流 256MB、单帧 8MB、push 每片 1MB。
package server

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	gwMaxStreamBytes = 256 * 1024 * 1024
	gwMaxFrameBytes  = 8 * 1024 * 1024
	gwPushChunk      = 1024 * 1024
)

// gwPending 是一条在途请求:onData 非空时 data 帧流式直通消费者(聚积跳过),
// 否则按序聚积、在 result 帧时拼装进 res.Bytes。
type gwPending struct {
	ch     chan deviceResult
	onData func([]byte)
}

// gwStream 是一个 reqId 的流式聚积状态(严格按 seq 排序,防乱序拼接)。
type gwStream struct {
	chunks  [][]byte
	bytes   int64
	nextSeq int
}

// gwTunConn 是隧道里的一条 TCP 连接:设备侧拨号完成前到达的字节先缓存,
// tcp_opened 后按序冲刷(与哨兵 buffers 语义一致)。
type gwTunConn struct {
	mu     sync.Mutex
	tcp    net.Conn
	opened bool
	buf    [][]byte
}

// gwTunnel 是一个本机监听 ↔ 设备端口的桥;tunnelId 注册在网关,设备断开时
// 整体销毁(监听关闭、全部连接拆线)。
type gwTunnel struct {
	deviceID   string
	targetHost string
	targetPort int
	ln         net.Listener
	port       int

	mu    sync.Mutex
	conns map[string]*gwTunConn
}

func (t *gwTunnel) close() {
	_ = t.ln.Close()
	t.mu.Lock()
	conns := make([]*gwTunConn, 0, len(t.conns))
	for _, c := range t.conns {
		conns = append(conns, c)
	}
	t.conns = map[string]*gwTunConn{}
	t.mu.Unlock()
	for _, c := range conns {
		_ = c.tcp.Close()
	}
}

// requestInternal 是 Request 的通用形态:onData 非空走流式路径。
func (g *DeviceGateway) requestInternal(deviceID string, frame map[string]any, timeout time.Duration, onData func([]byte)) (deviceResult, error) {
	g.mu.Lock()
	c := g.conns[deviceID]
	if c == nil {
		g.mu.Unlock()
		return deviceResult{}, fmt.Errorf("设备不在线(deviceId=%s)", deviceID)
	}
	idle := time.Since(c.lastFrame)
	stale := c.stale || idle > deviceStaleAfter
	g.mu.Unlock()
	if stale {
		return deviceResult{}, fmt.Errorf("设备无响应:已 %s 未收到心跳,请先在设备上唤醒 DroidBridge",
			idle.Round(time.Second))
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	reqID := fmt.Sprintf("d%d%d", time.Now().UnixNano(), g.counter.Add(1))
	ch := make(chan deviceResult, 1)
	g.pendMu.Lock()
	g.pending[reqID] = &gwPending{ch: ch, onData: onData}
	g.pendDev[reqID] = deviceID
	g.pendMu.Unlock()
	frame["reqId"] = reqID
	if err := g.sendJSON(c, frame); err != nil {
		g.dropPending(reqID)
		return deviceResult{}, fmt.Errorf("发送失败: %v", err)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res, nil
	case <-timer.C:
		g.dropPending(reqID)
		return deviceResult{}, fmt.Errorf("设备响应超时(%s)", timeout)
	}
}

// PullFile 把设备上的文件流式拉回并边收边写 w(大文件不占网关内存)。
// 返回聚合 result 与实际写入字节数。
func (g *DeviceGateway) PullFile(deviceID, path string, maxBytes int64, w io.Writer, timeout time.Duration) (deviceResult, int64, error) {
	if maxBytes <= 0 || maxBytes > gwMaxStreamBytes {
		maxBytes = gwMaxStreamBytes
	}
	var written int64
	var werr error
	onData := func(chunk []byte) {
		if werr != nil {
			return
		}
		n, err := w.Write(chunk)
		written += int64(n)
		if err != nil {
			werr = err
		}
	}
	res, err := g.requestInternal(deviceID, map[string]any{
		"t": "pull", "path": path, "maxBytes": maxBytes,
	}, timeout, onData)
	if werr != nil {
		return res, written, fmt.Errorf("写入本地文件失败: %v", werr)
	}
	return res, written, err
}

// PushFile 把一份字节分片推到设备(每片 1MB,seq 0 截断目标,末片 done 才有
// 应答——整份塞一帧会把手机端 app 撑到 OOM,哨兵踩过的坑照搬规避)。
// mode 形如 "0755"。超时下限按字节数放大(慢链路不误杀,地板 100KB/s)。
func (g *DeviceGateway) PushFile(deviceID, path string, data []byte, mode string, timeout time.Duration) (deviceResult, error) {
	if len(data) > gwMaxStreamBytes {
		return deviceResult{}, fmt.Errorf("文件 %d 字节超过上限 %d", len(data), gwMaxStreamBytes)
	}
	if mode == "" {
		mode = "0700"
	}
	if timeout < 30*time.Second+time.Duration(len(data)/100_000)*time.Second {
		timeout = 30*time.Second + time.Duration(len(data)/100_000)*time.Second
	}
	g.mu.Lock()
	c := g.conns[deviceID]
	if c == nil {
		g.mu.Unlock()
		return deviceResult{}, fmt.Errorf("设备不在线(deviceId=%s)", deviceID)
	}
	g.mu.Unlock()

	reqID := fmt.Sprintf("d%d%d", time.Now().UnixNano(), g.counter.Add(1))
	ch := make(chan deviceResult, 1)
	g.pendMu.Lock()
	g.pending[reqID] = &gwPending{ch: ch}
	g.pendDev[reqID] = deviceID
	g.pendMu.Unlock()

	total := (len(data) + gwPushChunk - 1) / gwPushChunk
	if total < 1 {
		total = 1
	}
	var sendErr error
	for seq := 0; seq < total; seq++ {
		end := (seq + 1) * gwPushChunk
		if end > len(data) {
			end = len(data)
		}
		frame := map[string]any{
			"t": "push", "reqId": reqID, "path": path, "seq": seq,
			"done": seq == total-1, "b64": base64.StdEncoding.EncodeToString(data[seq*gwPushChunk : end]),
			"mode": mode,
		}
		if err := g.sendJSON(c, frame); err != nil {
			sendErr = fmt.Errorf("发送失败(第 %d 片): %v", seq, err)
			break
		}
	}
	if sendErr != nil {
		g.dropPending(reqID)
		return deviceResult{}, sendErr
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res, nil
	case <-timer.C:
		g.dropPending(reqID)
		return deviceResult{}, fmt.Errorf("设备响应超时(%s)", timeout)
	}
}

// --- TCP 隧道 ---

// OpenTunnel 在本机 127.0.0.1 起一个随机端口监听,桥接到设备侧 host:port
// (frida 场景就是设备的 127.0.0.1:27042)。同设备同目标复用存活隧道。
func (g *DeviceGateway) OpenTunnel(deviceID, host string, port int) (int, error) {
	key := fmt.Sprintf("%s|%s:%d", deviceID, host, port)
	g.tunMu.Lock()
	if t := g.tunnels[key]; t != nil {
		p := t.port
		g.tunMu.Unlock()
		return p, nil
	}
	g.tunMu.Unlock()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("隧道监听失败: %v", err)
	}
	t := &gwTunnel{deviceID: deviceID, targetHost: host, targetPort: port,
		ln: ln, port: ln.Addr().(*net.TCPAddr).Port, conns: map[string]*gwTunConn{}}
	g.tunMu.Lock()
	// 并发下同 key 只留先注册者。
	if prev := g.tunnels[key]; prev != nil {
		_ = ln.Close()
		p := prev.port
		g.tunMu.Unlock()
		return p, nil
	}
	g.tunnels[key] = t
	g.tunMu.Unlock()

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go g.tunnelAccept(t, conn)
		}
	}()
	logTunnelf("[devices] 隧道开启:%s → 设备 %s 的 %s:%d(本机 127.0.0.1:%d)",
		key, deviceID, host, port, t.port)
	return t.port, nil
}

// tunnelAccept 处理一条进入本机监听的 TCP 连接:发 tcp_open,拨号完成前的
// 入站字节缓存,完成后由读循环冲刷。
func (g *DeviceGateway) tunnelAccept(t *gwTunnel, conn net.Conn) {
	g.mu.Lock()
	devConn := g.conns[t.deviceID]
	g.mu.Unlock()
	if devConn == nil {
		_ = conn.Close()
		return
	}
	connID := fmt.Sprintf("c%d", g.counter.Add(1))
	tc := &gwTunConn{tcp: conn}
	t.mu.Lock()
	t.conns[connID] = tc
	t.mu.Unlock()

	reqID := fmt.Sprintf("d%d%d", time.Now().UnixNano(), g.counter.Add(1))
	ch := make(chan deviceResult, 1)
	g.pendMu.Lock()
	g.pending[reqID] = &gwPending{ch: ch}
	g.pendDev[reqID] = t.deviceID
	g.pendMu.Unlock()
	if err := g.sendJSON(devConn, map[string]any{
		"t": "tcp_open", "reqId": reqID, "tunnelId": g.tunnelKeyOf(t),
		"connId": connID, "host": t.targetHost, "port": t.targetPort,
	}); err != nil {
		g.dropPending(reqID)
		g.tunnelDropConn(t, connID, "")
		return
	}
	// 设备侧拨号结果:失败即拆线(读循环在 tcp_opened 帧里 resolve)。
	go func() {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case res := <-ch:
			if !res.OK {
				g.tunnelDropConn(t, connID, "")
			}
		case <-timer.C:
			g.dropPending(reqID)
			g.tunnelDropConn(t, connID, "")
		}
	}()

	// 入站泵:客户端 → 设备。opened 之前先缓存(顺序保真),之后直发。
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				chunk := append([]byte{}, buf[:n]...)
				send := func() bool {
					tc.mu.Lock()
					defer tc.mu.Unlock()
					if !tc.opened {
						tc.buf = append(tc.buf, chunk)
						return true
					}
					return g.sendJSON(devConn, map[string]any{
						"t": "tcp_send", "tunnelId": g.tunnelKeyOf(t),
						"connId": connID, "b64": base64.StdEncoding.EncodeToString(chunk),
					}) == nil
				}
				if !send() {
					break
				}
			}
			if rerr != nil {
				g.tunnelDropConn(t, connID, "tcp_close")
				return
			}
		}
	}()
}

// tunnelKeyOf 由隧道反查注册键(帧里要带 tunnelId)。
func (g *DeviceGateway) tunnelKeyOf(t *gwTunnel) string {
	return fmt.Sprintf("%s|%s:%d", t.deviceID, t.targetHost, t.targetPort)
}

// tunnelDropConn 拆一条隧道连接;closeFrame 非空时向设备补发对应帧。
func (g *DeviceGateway) tunnelDropConn(t *gwTunnel, connID, closeFrame string) {
	t.mu.Lock()
	c := t.conns[connID]
	delete(t.conns, connID)
	t.mu.Unlock()
	if c == nil {
		return
	}
	if closeFrame != "" {
		g.mu.Lock()
		devConn := g.conns[t.deviceID]
		g.mu.Unlock()
		if devConn != nil {
			_ = g.sendJSON(devConn, map[string]any{
				"t": closeFrame, "tunnelId": g.tunnelKeyOf(t), "connId": connID,
			})
		}
	}
	_ = c.tcp.Close()
}

// handleDataFrame 处理设备 → 服务端的 data 帧:严格 seq 排序、256MB 上限;
// 有 onData 直通,否则聚积到流,由 result 帧拼装。
func (g *DeviceGateway) handleDataFrame(reqID string, seq int, b64 string) {
	g.pendMu.Lock()
	p := g.pending[reqID]
	if p == nil {
		g.pendMu.Unlock()
		return
	}
	st := g.streams[reqID]
	if st == nil {
		st = &gwStream{}
		g.streams[reqID] = st
	}
	if seq != st.nextSeq {
		delete(g.streams, reqID)
		g.pendMu.Unlock()
		g.failPending(reqID, fmt.Sprintf("流分片乱序:期望 %d,收到 %d", st.nextSeq, seq))
		return
	}
	st.nextSeq++
	chunk, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		delete(g.streams, reqID)
		g.pendMu.Unlock()
		g.failPending(reqID, "data 帧 base64 解码失败")
		return
	}
	st.bytes += int64(len(chunk))
	if st.bytes > gwMaxStreamBytes {
		delete(g.streams, reqID)
		g.pendMu.Unlock()
		g.failPending(reqID, "流超过大小上限")
		return
	}
	if p.onData != nil {
		g.pendMu.Unlock()
		p.onData(chunk)
		return
	}
	st.chunks = append(st.chunks, chunk)
	g.pendMu.Unlock()
}

// handleTcpDeviceFrame 处理 tcp_opened / tcp_data / tcp_closed 三种设备帧。
func (g *DeviceGateway) handleTcpDeviceFrame(frameT, tunnelID, connID, reqID, b64 string, ok bool, errText string) {
	g.tunMu.Lock()
	t := g.tunnels[tunnelID]
	g.tunMu.Unlock()
	if t == nil {
		return
	}
	switch frameT {
	case "tcp_opened":
		if reqID != "" {
			g.resolveResult(reqID, deviceResult{OK: ok, Error: errText})
		}
		if !ok {
			g.tunnelDropConn(t, connID, "")
			return
		}
		t.mu.Lock()
		tc := t.conns[connID]
		if tc == nil {
			t.mu.Unlock()
			return
		}
		tc.mu.Lock()
		buffered := tc.buf
		tc.buf = nil
		tc.opened = true
		tc.mu.Unlock()
		t.mu.Unlock()
		g.mu.Lock()
		devConn := g.conns[t.deviceID]
		g.mu.Unlock()
		if devConn == nil {
			g.tunnelDropConn(t, connID, "")
			return
		}
		for _, chunk := range buffered {
			_ = g.sendJSON(devConn, map[string]any{
				"t": "tcp_send", "tunnelId": tunnelID, "connId": connID,
				"b64": base64.StdEncoding.EncodeToString(chunk),
			})
		}
	case "tcp_data":
		t.mu.Lock()
		tc := t.conns[connID]
		t.mu.Unlock()
		if tc == nil {
			return
		}
		chunk, derr := base64.StdEncoding.DecodeString(b64)
		if derr != nil || len(chunk) == 0 {
			return
		}
		_ = tc.tcp.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, werr := tc.tcp.Write(chunk); werr != nil {
			g.tunnelDropConn(t, connID, "tcp_close")
		}
	case "tcp_closed":
		g.tunnelDropConn(t, connID, "")
	}
}

// closeTunnelsOf 设备断开时销毁它的全部隧道(监听与连接一并拆)。
func (g *DeviceGateway) closeTunnelsOf(deviceID string) {
	g.tunMu.Lock()
	var doomed []*gwTunnel
	for key, t := range g.tunnels {
		if t.deviceID == deviceID {
			doomed = append(doomed, t)
			delete(g.tunnels, key)
		}
	}
	g.tunMu.Unlock()
	for _, t := range doomed {
		t.close()
		logTunnelf("[devices] 设备 %s 离线,隧道 %s 已销毁", deviceID, g.tunnelKeyOf(t))
	}
}

// failPending 让一条在途请求立即失败(流乱序/超限等)。
func (g *DeviceGateway) failPending(reqID, reason string) {
	g.pendMu.Lock()
	p := g.pending[reqID]
	delete(g.pending, reqID)
	delete(g.pendDev, reqID)
	delete(g.streams, reqID)
	g.pendMu.Unlock()
	if p != nil {
		p.ch <- deviceResult{OK: false, Error: reason}
	}
}

// assembleStream 在 result 帧到达时把聚积的流拼进应答(无 onData 的路径)。
func (g *DeviceGateway) assembleStream(reqID string, res *deviceResult) {
	g.pendMu.Lock()
	st := g.streams[reqID]
	delete(g.streams, reqID)
	g.pendMu.Unlock()
	if st != nil && len(st.chunks) > 0 {
		res.Bytes = bytes.Join(st.chunks, nil)
	}
}

func logTunnelf(format string, args ...any) {
	log.Printf(format, args...)
}
