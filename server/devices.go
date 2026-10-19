// devices.go 装配 Android 反连设备子系统:init(devStore + 网关 + 独立监听)、
// host 工具(list_devices/probe_device/device_exec/droid_unpack/apk_packer_check,
// 默认绑 worker)、REST(/api/devices,JWT 后的人工通道)。协议见
// droidgateway.go 与 droidstream.go(期 2 传输层);表见 db/devices.go。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/skip2/go-qrcode"
)

// 反连监听默认值:loopback + 8791(设备联调时设 ARTEX_DEVICE_LISTEN=0.0.0.0:8791
// 或在设备页改绑)。设 off 关闭。
const (
	deviceListenEnv  = "ARTEX_DEVICE_LISTEN"
	deviceDefaultLsn = "127.0.0.1:8791"
	deviceProbeCmd   = "id" // probe 往返用 exec 跑的最小无害命令
)

// taskReverse 判定任务是否为逆向任务(worker.reverse 提示词变体的开关):
// 按 description/goal 关键词命中(逆向/反编译/脱壳/APK/DEX/SO/wxapkg/固件/算法还原
// /加密还原/协议还原)。误判后果轻(仅切换提示词变体,能力不受限);worker 每次
// run 现查,任务描述修改即时生效;读取失败按普通任务处理(不误切)。
func (s *Server) taskReverse(taskID int64) bool {
	if taskID <= 0 || s.m == nil || s.m.pg == nil {
		return false
	}
	t, err := s.m.pg.GetTask(taskID)
	if err != nil || t == nil {
		return false
	}
	text := t.Description + "\n" + t.Goal
	for _, kw := range []string{"逆向", "反编译", "脱壳", "apk", "apk包", "dex", "so文件", "wxapkg", "小程序包", "固件", "算法还原", "加密还原", "协议还原", "样本分析"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// auditDevices 打设备人工操作审计日志(操作者/来源地址/动作明细)。
func (s *Server) auditDevices(r *http.Request, format string, args ...any) {
	op := "unknown"
	if tok := extractToken(r); tok != "" {
		if claims, err := parseAccessToken(tok, s.jwtKey); err == nil && claims.Subject != "" {
			op = claims.Subject
		}
	}
	log.Printf("[devices] op=%s remote=%s %s", op, r.RemoteAddr, fmt.Sprintf(format, args...))
}

// initDevices 建设备落库层与反连网关;启动诚实化:平台重启 = 全量 offline
// (与 initReverse 同一取向)。独立监听按环境变量起(默认 127.0.0.1:8791)。
func (s *Server) initDevices() {
	if s.m.pg == nil {
		return
	}
	s.devStore = db.NewDeviceStore(s.m.pg, s.jwtKey)
	if n, err := s.devStore.MarkAllOffline(s.ctx); err != nil {
		log.Printf("[devices] 启动诚实化失败: %v", err)
	} else if n > 0 {
		log.Printf("[devices] 启动诚实化:%d 台上期在线设备标 offline", n)
	}
	s.devGW = newDeviceGateway(s.devStore)
	go func() { <-s.ctx.Done(); s.devGW.Close() }()
	addr := strings.TrimSpace(os.Getenv(deviceListenEnv))
	if addr == "" {
		addr = deviceDefaultLsn
	}
	if strings.EqualFold(addr, "off") {
		log.Printf("[devices] 反连监听已按 %s=off 关闭", deviceListenEnv)
		return
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("[devices] %s 非法(%s),监听未起: %v", deviceListenEnv, addr, err)
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		log.Printf("[devices] %s 端口非法(%s),监听未起", deviceListenEnv, addr)
		return
	}
	if err := s.devGW.Listen(host, p); err != nil {
		log.Printf("[devices] 反连监听未起: %v", err)
	}
}

// devicesReady 路由级前置:子系统未就绪时写 503。
func (s *Server) devicesReady(w http.ResponseWriter) bool {
	if s.devStore == nil || s.devGW == nil {
		writeErr(w, 503, "设备子系统未就绪(DB 未连接)")
		return false
	}
	return true
}

// --- host 工具(默认绑 worker)---

func devicePerm(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}

func (s *Server) deviceTools() []actool.CoreTool {
	if s.devStore == nil || s.devGW == nil {
		return nil
	}
	return []actool.CoreTool{s.listDevicesTool(), s.probeDeviceTool(), s.deviceExecTool(),
		s.droidUnpackTool(), s.apkPackerCheckTool()}
}

// deviceExecTool 经反连通道在设备上执行 shell 命令(设备侧能力解锁:DroidBridge
// exec 帧,APK 侧 asRoot 走 su -c)。输出与会话工具同款 64KB 截断标注。
func (s *Server) deviceExecTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "device_exec",
		Description: "在 Android 测试设备(DroidBridge 反连)上执行一条 shell 命令并取回 stdout/stderr。" +
			"asRoot=true 经 su(root 设备);超时默认 15s、上限 120s;输出超 64KB 截断标注。" +
			"设备不在线/无响应(45s 无心跳冻结)会明确报因。典型用途:定位/读取小程序 wxapkg、" +
			"读小程序 storage 提取 token、设备侧诊断。注意 OPSEC:命令在真机执行留痕,写操作慎用。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"device_id": strParam("list_devices 返回的 device_id(或行 id)"),
				"command":   strParam("要在设备上执行的 shell 命令"),
				"as_root":   map[string]any{"type": "boolean", "description": "经 su 执行(默认 false)"},
				"timeout":   map[string]any{"type": "integer", "description": "超时秒数(默认 15,上限 120)"},
			},
			"required": []any{"device_id", "command"},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: devicePerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				DeviceID string `json:"device_id"`
				Command  string `json:"command"`
				AsRoot   bool   `json:"as_root"`
				Timeout  int    `json:"timeout"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Command) == "" {
				return actool.Errorf("command 必填"), nil
			}
			rec, err := s.lookupDevice(a.DeviceID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Timeout <= 0 {
				a.Timeout = 15
			}
			if a.Timeout > 120 {
				a.Timeout = 120
			}
			start := time.Now()
			res, rerr := s.devGW.Request(rec.DeviceID, map[string]any{
				"t": "exec", "cmd": a.Command, "asRoot": a.AsRoot,
				"timeoutMs": a.Timeout * 1000,
			}, time.Duration(a.Timeout+5)*time.Second)
			if rerr != nil {
				return actool.Errorf("执行失败:" + rerr.Error()), nil
			}
			ms := time.Since(start).Milliseconds()
			if !res.OK && res.Stdout == "" && res.Stderr == "" {
				return actool.Errorf(fmt.Sprintf("执行失败(code=%d):%s", res.Code, orDefault(res.Error, "未知错误"))), nil
			}
			out := map[string]any{"device_id": rec.DeviceID, "code": res.Code, "ms": ms}
			out["stdout"] = truncateOutput(res.Stdout)
			out["stderr"] = truncateOutput(res.Stderr)
			if len(res.Stdout) > maxSessionToolOutput || len(res.Stderr) > maxSessionToolOutput {
				out["truncated"] = true
			}
			if res.Error != "" {
				out["error"] = res.Error
			}
			return jsonResult(out)
		},
	})
}

// deviceView 把 DB 行 + 网关运行态合成一个投影(工具与 REST 共用)。
func (s *Server) deviceView(rec *db.DeviceRecord) map[string]any {
	item := map[string]any{
		"id": rec.ID, "device_id": rec.DeviceID, "name": rec.Name,
		"model": rec.Model, "android_version": rec.AndroidVersion, "sdk_int": rec.SdkInt,
		"rooted": rec.Rooted, "status": rec.Status, "node_id": rec.NodeID,
		"last_seen": rec.LastSeen, "created_at": rec.CreatedAt,
	}
	idle, stale, online := s.devGW.Liveness(rec.DeviceID)
	if online {
		item["online"] = true
		item["idle_ms"] = idle.Milliseconds()
		item["stale"] = stale
		if stale {
			item["state"] = "unresponsive"
		} else {
			item["state"] = "online"
		}
	} else {
		item["online"] = false
		item["stale"] = false
		item["state"] = "offline"
	}
	return item
}

// listDevicesTool 让 worker 看到全部登记设备的实时判活状态。
func (s *Server) listDevicesTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "list_devices",
		Description: "列出平台登记的 Android 测试设备(DroidBridge 反连)及实时判活状态:" +
			"state=online(在线且心跳正常)/unresponsive(连接还在但 45s 无帧,进程可能被冻结)/offline(未连接)。" +
			"返回 device_id(后续 probe_device 用它)、机型、Android 版本、root、空闲毫秒数。" +
			"设备端是 DroidBridge APK 反连:离线设备需在实体机上唤醒 DroidBridge,平台侧无法拉起。",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: devicePerm,
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			recs, err := s.devStore.List(ctx)
			if err != nil {
				return actool.Errorf("设备台账读取失败:" + err.Error()), nil
			}
			items := []map[string]any{}
			for _, rec := range recs {
				items = append(items, s.deviceView(rec))
			}
			if host, port, on := s.devGW.ListenInfo(); on {
				return jsonResult(map[string]any{"items": items, "listen": net.JoinHostPort(host, strconv.Itoa(port))})
			}
			return jsonResult(map[string]any{"items": items, "listen": ""})
		},
	})
}

// probeDeviceTool 对设备发一次 exec id 往返(5s 超时):设备真实执行了命令才算活
// (心跳只证明进程在跑,不证明通道可用)。无响应/超时如实报因。
func (s *Server) probeDeviceTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "probe_device",
		Description: "对一台已登记的 Android 设备做判活探测:经反连通道发 exec id(5s 超时)," +
			"设备真实执行并回包才算活;连接在但无响应(45s 无心跳,进程可能被冻结)或已离线都会明确报因。" +
			"入参用 list_devices 返回的 device_id(也接受行 id)。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"device_id": strParam("list_devices 返回的 device_id(或行 id)"),
			},
			"required": []any{"device_id"},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: devicePerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				DeviceID string `json:"device_id"`
			}
			_ = json.Unmarshal(in, &a)
			out, err := s.probeDevice(a.DeviceID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(out)
		},
	})
}

// probeDevice 判活核心(工具与 REST 共用):exec id 往返,5s 超时。
func (s *Server) probeDevice(idOrDeviceID string) (map[string]any, error) {
	rec, err := s.lookupDevice(idOrDeviceID)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	res, rerr := s.devGW.Request(rec.DeviceID, map[string]any{
		"t": "exec", "cmd": deviceProbeCmd, "asRoot": false, "timeoutMs": 4000,
	}, 5*time.Second)
	ms := time.Since(start).Milliseconds()
	out := map[string]any{"device_id": rec.DeviceID, "id": rec.ID, "ms": ms}
	if rerr != nil {
		out["alive"] = false
		out["error"] = rerr.Error()
		return out, nil
	}
	out["alive"] = res.OK
	out["stdout"] = strings.TrimSpace(res.Stdout)
	if res.Error != "" {
		out["error"] = res.Error
	}
	return out, nil
}

// lookupDevice 按 device_id 或行 id 取设备行。
func (s *Server) lookupDevice(idOrDeviceID string) (*db.DeviceRecord, error) {
	v := strings.TrimSpace(idOrDeviceID)
	if v == "" {
		return nil, fmt.Errorf("device_id 必填")
	}
	recs, err := s.devStore.List(context.Background())
	if err != nil {
		return nil, fmt.Errorf("设备台账读取失败: %v", err)
	}
	for _, rec := range recs {
		if rec.DeviceID == v {
			return rec, nil
		}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		for _, rec := range recs {
			if rec.ID == n {
				return rec, nil
			}
		}
	}
	return nil, fmt.Errorf("设备 %s 不存在(未登记或已删除)", v)
}

// seedDeviceTools 把设备工具 seed 进 tools 表。绑定面与既有安卓工具一致
// (worker + mainagent/auto + pentest 族 + android.pentest/android.reverse/
// reverse.frida 变体),保证安卓任务模板的 agent 能看到 droid_unpack 等新工具。
// (SeedTool 首插入语义:老库的用户编辑不被覆盖。)
func (s *Server) seedDeviceTools() {
	agents, _ := json.Marshal([]string{"worker", "mainagent", "auto", "pentest",
		"android.pentest", "android.reverse", "reverse.frida"})
	for _, t := range s.deviceTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

// --- REST(JWT 后人工通道) ---

// deviceWSURL 生成设备页展示的接入地址:监听绑通配地址时用回连地址或请求
// Host 的主机部分替换(手机不可能连 0.0.0.0)。
func (s *Server) deviceWSURL(r *http.Request) string {
	host, port, ok := s.devGW.ListenInfo()
	if !ok {
		return ""
	}
	display := host
	if host == "0.0.0.0" || host == "::" {
		if cb, err := callbackHost(); err == nil && cb != "" && !isLoopbackHost(cb) {
			display = cb
		} else if r != nil {
			if h, _, err := net.SplitHostPort(r.Host); err == nil && h != "" && !isLoopbackHost(h) {
				display = h
			}
		}
		// 回环请求 + 未配回连地址时,用本机首个非回环 IPv4(手机侧能拨的地址)。
		if isLoopbackHost(display) {
			if lan := lanIPv4(); lan != "" {
				display = lan
			}
		}
	}
	return fmt.Sprintf("ws://%s:%d/ws/droid", display, port)
}

// isLoopbackHost 判定展示用主机名是否回环/通配(手机不可拨)。
func isLoopbackHost(h string) bool {
	if h == "0.0.0.0" || h == "::" || h == "" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// lanIPv4 取本机首个非回环 IPv4(网卡枚举失败返回空)。
// 按接口枚举并跳过回环接口:InterfaceAddrs 不带接口归属,WSL2 的 DNS 隧道
// 地址 10.255.255.254/32 挂在 lo 上,按地址过滤会把它误选为局域网地址。
func lanIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if v4 := lanIPv4Of(iface.Flags, addrs); v4 != "" {
			return v4
		}
	}
	return ""
}

// lanIPv4Of 从单个接口的地址列表挑首个可用 IPv4;接口回环或未启用时返回空。
func lanIPv4Of(flags net.Flags, addrs []net.Addr) string {
	if flags&net.FlagLoopback != 0 || flags&net.FlagUp == 0 {
		return ""
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			if v4 := ipNet.IP.To4(); v4 != nil && !v4.IsLoopback() && !v4.IsLinkLocalUnicast() {
				return v4.String()
			}
		}
	}
	return ""
}

// GET /api/devices — 台账 + 实时判活 + 监听信息。
func (s *Server) devicesList(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	recs, err := s.devStore.List(r.Context())
	if err != nil {
		writeErr(w, 500, "设备台账读取失败: "+err.Error())
		return
	}
	items := []map[string]any{}
	for _, rec := range recs {
		items = append(items, s.deviceView(rec))
	}
	host, port, on := s.devGW.ListenInfo()
	writeJSON(w, 200, map[string]any{
		"items":  items,
		"listen": map[string]any{"host": host, "port": port, "enabled": on},
		"ws_url": s.deviceWSURL(r),
	})
}

// POST /api/devices {name} — 登记:生成 token,明文仅本次返回。
func (s *Server) devicesEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	var a struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&a)
	rec, token, err := s.devStore.Enroll(r.Context(), strings.TrimSpace(a.Name))
	if err != nil {
		writeErr(w, 500, "登记失败: "+err.Error())
		return
	}
	s.auditDevices(r, "enroll id=%d name=%q", rec.ID, rec.Name)
	writeJSON(w, 201, map[string]any{
		"id": rec.ID, "name": rec.Name, "token": token, "ws_url": s.deviceWSURL(r),
		"hint": "把 ws_url 与 token 填进手机 DroidBridge(Server URL / Token),deviceId 由 App 生成、首连自动绑定",
	})
}

// GET /api/devices/{id}/qr — 接入二维码 PNG(内容 = ws://…/ws/droid?token=…,
// DroidBridge「扫码填入」一键配置)。token 属敏感载荷:审计必记 + no-store;
// 鉴权复用 SSE 同款一次性 ticket(requireAuth 的 ?ticket= 通道,60s 用后即焚),
// 供 <img> 直连(它带不了 Authorization 头)。
func (s *Server) devicesQR(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	token, err := s.devStore.RevealToken(r.Context(), id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	content := s.deviceWSURL(r) + "?token=" + token
	png, err := qrcode.Encode(content, qrcode.Medium, 512)
	if err != nil {
		writeErr(w, 500, "二维码生成失败: "+err.Error())
		return
	}
	s.auditDevices(r, "qr id=%d", id)
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// POST /api/devices/{id}/reveal — 重显 token(密文解密;审计必记)。
func (s *Server) devicesReveal(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	token, err := s.devStore.RevealToken(r.Context(), id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	s.auditDevices(r, "reveal token id=%d", id)
	writeJSON(w, 200, map[string]any{"id": id, "token": token, "ws_url": s.deviceWSURL(r)})
}

// DELETE /api/devices/{id} — 踢线 + 删除(幂等)。
func (s *Server) devicesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rec, err := s.devStore.Get(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "设备读取失败: "+err.Error())
		return
	}
	if rec == nil {
		writeJSON(w, 200, map[string]any{"ok": true, "id": id, "was_live": false})
		return
	}
	if rec.DeviceID != "" {
		s.devGW.Disconnect(rec.DeviceID)
	}
	if err := s.devStore.Delete(r.Context(), id); err != nil {
		writeErr(w, 500, "设备删除失败: "+err.Error())
		return
	}
	s.auditDevices(r, "delete id=%d device_id=%s", id, rec.DeviceID)
	writeJSON(w, 200, map[string]any{"ok": true, "id": id, "was_live": rec.Status == db.DeviceOnline})
}

// POST /api/devices/{id}/probe — 人工判活(exec id 往返,5s)。
func (s *Server) devicesProbe(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rec, err := s.devStore.Get(r.Context(), id)
	if err != nil || rec == nil {
		if rec == nil {
			writeErr(w, 404, fmt.Sprintf("设备 %d 不存在", id))
			return
		}
		writeErr(w, 500, "设备读取失败: "+err.Error())
		return
	}
	out, perr := s.probeDevice(strconv.FormatInt(rec.ID, 10))
	if perr != nil {
		writeErr(w, 404, perr.Error())
		return
	}
	s.auditDevices(r, "probe id=%d alive=%v ms=%v err=%v", id, out["alive"], out["ms"], out["error"])
	writeJSON(w, 200, out)
}

// GET /api/devices/listen — 当前反连监听。
func (s *Server) devicesListenGet(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	host, port, on := s.devGW.ListenInfo()
	writeJSON(w, 200, map[string]any{"host": host, "port": port, "enabled": on})
}

// POST /api/devices/listen {host, port} — 起/重绑独立监听(通配地址供手机接入)。
func (s *Server) devicesListenSet(w http.ResponseWriter, r *http.Request) {
	if !s.devicesReady(w) {
		return
	}
	var a struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeErr(w, 400, "请求体 JSON 解析失败: "+err.Error())
		return
	}
	a.Host = strings.TrimSpace(a.Host)
	if a.Host == "" {
		a.Host = "127.0.0.1"
	}
	if a.Port <= 0 {
		a.Port = 8791
	}
	if err := s.devGW.Listen(a.Host, a.Port); err != nil {
		s.auditDevices(r, "listen %s:%d 失败: %v", a.Host, a.Port, err)
		writeErr(w, 502, err.Error())
		return
	}
	s.auditDevices(r, "listen %s:%d", a.Host, a.Port)
	writeJSON(w, 200, map[string]any{"ok": true, "host": a.Host, "port": a.Port})
}
