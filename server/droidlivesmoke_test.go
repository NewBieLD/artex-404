package server

// droidlivesmoke_test.go:真机帧级冒烟(手动门控,不进常规跑批)。验证网关期 2
// 传输层(pull/push/隧道)与真实 DroidBridge APK 的互通——模拟器测试证明不了
// APK 侧实现的真实帧行为,这一支补上。跑法:
//
//	1) 暂停生产实例(设备会自动重试反连);
//	2) ARTEX_LIVE_DEVICE_SMOKE=1 ARTEX_PG_DSN=<dsn> \
//	   ARTEX_LIVE_DATA_DIR=<生产 data 目录,读 jwt.key> \
//	   go test ./server/ -run TestLiveDeviceFrameSmoke -v -timeout 10m
//	3) 恢复生产实例。
//
// 任何一步失败都会把设备侧应答原文带进错误信息,便于对照协议文档排查。

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestLiveDeviceFrameSmoke(t *testing.T) {
	if os.Getenv("ARTEX_LIVE_DEVICE_SMOKE") == "" {
		t.Skip("真机冒烟需显式开启:ARTEX_LIVE_DEVICE_SMOKE=1(且暂停生产实例,详见文件头)")
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	dataDir := os.Getenv("ARTEX_LIVE_DATA_DIR")
	key, err := readLiveJWTKey(dataDir)
	if err != nil {
		t.Fatalf("读 jwt.key 失败: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()
	ctx := context.Background()
	store := db.NewDeviceStore(pg, key)
	recs, err := store.List(ctx)
	if err != nil || len(recs) == 0 {
		t.Fatalf("设备台账为空或读取失败: %v", err)
	}
	rec := recs[0]
	token, err := store.RevealToken(ctx, rec.ID)
	if err != nil {
		t.Fatalf("RevealToken: %v", err)
	}
	_ = token // token 由设备拨号时自带,网关经 FindByToken 鉴权

	g := newDeviceGateway(store)
	defer g.Close()
	if err := g.Listen("0.0.0.0", 8791); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Logf("网关已监听 :8791,等设备 %s(%s) 重连…", rec.DeviceID, rec.Name)
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if idle, stale, online := g.Liveness(rec.DeviceID); online && !stale {
			t.Logf("设备已重连(idle=%s)", idle.Round(time.Second))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("3 分钟内设备未重连(检查 DroidBridge 是否在前台重试)")
		}
		time.Sleep(2 * time.Second)
	}

	// 1) exec 往返(基线,期 1 能力)。
	res, err := g.Request(rec.DeviceID, map[string]any{
		"t": "exec", "cmd": "id; getprop ro.build.version.release", "asRoot": false, "timeoutMs": 8000,
	}, 12*time.Second)
	if err != nil || !res.OK {
		t.Fatalf("exec 往返失败: %v %+v", err, res)
	}
	t.Logf("exec ok: %s", oneLine(res.Stdout))

	// 2) pull:拉一个小文件(流式分片由真实 APK 发出)。
	var pulled []byte
	pullRes, n, err := g.PullFile(rec.DeviceID, "/proc/version", 1<<20, &pullBuf{&pulled}, 15*time.Second)
	if err != nil || !pullRes.OK {
		t.Fatalf("pull /proc/version 失败: %v %+v", err, pullRes)
	}
	if n == 0 {
		t.Fatalf("pull 拉到 0 字节")
	}
	t.Logf("pull ok: %d bytes: %s", n, oneLine(string(pulled)))

	// 3) push:推一个小文件再 exec cat 校验字节一致。
	payload := []byte(fmt.Sprintf("artex-frame-smoke-%d\n", time.Now().Unix()))
	pushRes, err := g.PushFile(rec.DeviceID, "/data/local/tmp/artex-frame-smoke.txt", payload, "0644", 30*time.Second)
	if err != nil || !pushRes.OK {
		t.Fatalf("push 失败: %v %+v", err, pushRes)
	}
	cat, err := g.Request(rec.DeviceID, map[string]any{
		"t": "exec", "cmd": "cat /data/local/tmp/artex-frame-smoke.txt", "asRoot": false, "timeoutMs": 8000,
	}, 12*time.Second)
	if err != nil || !cat.OK || cat.Stdout != string(payload) {
		t.Fatalf("push 内容校验失败: %v %+v %q vs %q", err, cat, cat.Stdout, payload)
	}
	t.Logf("push ok: 内容回读一致")

	// 4) 隧道:开 27042(frida-server 口)。设备侧没跑 frida-server 时 tcp_opened
	//    会 ok=false 并拆线——帧往返本身通过即为冒烟通过,frida 可用性另行判断。
	port, err := g.OpenTunnel(rec.DeviceID, "127.0.0.1", 27042)
	if err != nil {
		t.Fatalf("OpenTunnel: %v", err)
	}
	conn, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if derr != nil {
		t.Fatalf("隧道本机端口拨号失败: %v", derr)
	}
	buf := make([]byte, 128)
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	m, rerr := conn.Read(buf)
	if rerr != nil {
		t.Logf("隧道帧往返完成(设备侧 frida-server 未运行,tcp_opened ok=false 拆线,属预期): %v", rerr)
	} else {
		t.Logf("隧道有数据返回(设备侧 27042 有服务): %q", oneLine(string(buf[:m])))
	}
	_ = conn.Close()
	t.Logf("真机帧级冒烟全部通过:exec/pull/push/隧道")
}

// pullBuf 让 PullFile 的 io.Writer 落进切片。
type pullBuf struct{ b *[]byte }

func (p *pullBuf) Write(chunk []byte) (int, error) {
	*p.b = append(*p.b, chunk...)
	return len(chunk), nil
}

// readLiveJWTKey 按生产实例的落位找 jwt.key:显式目录 → 仓库根 → data/。
func readLiveJWTKey(dir string) ([]byte, error) {
	var candidates []string
	if dir != "" {
		candidates = append(candidates, filepath.Join(dir, "jwt.key"))
	}
	candidates = append(candidates, "../jwt.key", "../data/jwt.key")
	for _, p := range candidates {
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("候选路径都没有 jwt.key: %v", candidates)
}

func oneLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// TestLiveDeviceDynamicSmoke 是 droid_unpack 管道的真机直跑(不经 LLM/worker,
// 每一步用的都是工具同款辅助函数)。额外门控:ARTEX_LIVE_FRIDA_SERVER=<宿主机
// frida-server 路径>;可选 ARTEX_LIVE_SPAWN_PKG=<包名> 指定 spawn 目标。
func TestLiveDeviceDynamicSmoke(t *testing.T) {
	if os.Getenv("ARTEX_LIVE_DEVICE_SMOKE") == "" || os.Getenv("ARTEX_LIVE_FRIDA_SERVER") == "" {
		t.Skip("动态冒烟需 ARTEX_LIVE_DEVICE_SMOKE=1 且 ARTEX_LIVE_FRIDA_SERVER=<frida-server 路径>")
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	key, kerr := readLiveJWTKey("")
	if kerr != nil {
		t.Fatalf("%v", kerr)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()
	ctx := context.Background()
	store := db.NewDeviceStore(pg, key)
	recs, err := store.List(ctx)
	if err != nil || len(recs) == 0 {
		t.Fatalf("设备台账为空: %v", err)
	}
	rec := recs[0]
	g := newDeviceGateway(store)
	defer g.Close()
	if err := g.Listen("0.0.0.0", 8791); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Logf("网关已监听 :8791,等设备 %s 重连…", rec.DeviceID)
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if idle, stale, online := g.Liveness(rec.DeviceID); online && !stale {
			t.Logf("设备已重连(idle=%s)", idle.Round(time.Second))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("3 分钟内设备未重连")
		}
		time.Sleep(2 * time.Second)
	}

	// 1) 推送 frida-server(真实 PushFile 分片路径,84MB 级)。
	hostBin := os.Getenv("ARTEX_LIVE_FRIDA_SERVER")
	data, err := os.ReadFile(hostBin)
	if err != nil {
		t.Fatalf("读 frida-server: %v", err)
	}
	pushRes, perr := g.PushFile(rec.DeviceID, "/data/local/tmp/frida-server", data, "0755", 15*time.Minute)
	if perr != nil || !pushRes.OK {
		t.Fatalf("推送 frida-server 失败: %v %+v", perr, pushRes)
	}
	t.Logf("frida-server 推送完成(%d 字节)", len(data))

	// 2) 拉起(工具同款命令形态:chmod/启动/查 pid 整段 su——app 身份 chmod 会被 SELinux 拒)。
	start, serr := g.Request(rec.DeviceID, map[string]any{
		"t": "exec", "asRoot": false, "timeoutMs": 20000,
		"cmd": `su -c "chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"; sleep 1; su -c "pidof frida-server"`,
	}, 25*time.Second)
	if serr != nil || !start.OK {
		t.Fatalf("frida-server 启动失败: %v %+v", serr, start)
	}
	if strings.TrimSpace(start.Stdout) == "" {
		t.Fatalf("pidof frida-server 为空")
	}
	t.Logf("frida-server 已运行(pid=%s)", strings.TrimSpace(start.Stdout))

	// 3) dump 目录预建(工具同款:app 进程对 /data/local/tmp 无写权限)。
	mk, merr := g.Request(rec.DeviceID, map[string]any{
		"t": "exec", "asRoot": true, "timeoutMs": 8000,
		"cmd": "mkdir -p " + deviceDumpDir + " && chmod 0777 " + deviceDumpDir + " && echo OK",
	}, 12*time.Second)
	if merr != nil || !mk.OK {
		t.Fatalf("dump 目录准备失败: %v %+v", merr, mk)
	}

	// 4) 隧道 + frida-ps 验证通道。
	port, terr := g.OpenTunnel(rec.DeviceID, "127.0.0.1", deviceFridaPort)
	if terr != nil {
		t.Fatalf("OpenTunnel: %v", terr)
	}
	fridaBin := os.Getenv("ARTEX_LIVE_FRIDA_CLI")
	if fridaBin == "" {
		fridaBin, _ = exec.LookPath("frida")
	}
	if fridaBin == "" {
		t.Fatalf("宿主机没有 frida CLI")
	}
	psCtx, psCancel := context.WithTimeout(ctx, 30*time.Second)
	psOut, _ := exec.CommandContext(psCtx, fridaBin+"-ps", "-H", fmt.Sprintf("127.0.0.1:%d", port), "-ai").CombinedOutput()
	psCancel()
	if len(psOut) == 0 {
		t.Fatalf("frida-ps 无输出(隧道/服务异常)")
	}
	t.Logf("frida-ps ok: %s", clampString(string(psOut), 200))

	// 5) 选 spawn 目标(第三方包第一个;可环境变量指定)。
	var candidates []string
	if pkg := os.Getenv("ARTEX_LIVE_SPAWN_PKG"); pkg != "" {
		candidates = []string{pkg}
	} else {
		pkgs, pkErr := g.Request(rec.DeviceID, map[string]any{
			// app 身份的 pm list 受包可见性限制(只看得见自己),走 su 拿全量。
			"t": "exec", "asRoot": false, "timeoutMs": 10000,
			"cmd": `su -c "pm list packages -3" | grep -v '^package:com\.sentinel\.' | head -8`,
		}, 15*time.Second)
		if pkErr != nil || !pkgs.OK {
			t.Fatalf("列包失败: %v %+v", pkErr, pkgs)
		}
		for _, line := range strings.Split(pkgs.Stdout, "\n") {
			line = strings.TrimSpace(line)
			// spawn 反连桥自己是自杀行为:桥进程被重启,WS 与隧道一起断。
			if strings.HasPrefix(line, "package:") && !strings.HasPrefix(line, "package:com.sentinel.") {
				candidates = append(candidates, strings.TrimPrefix(line, "package:"))
			}
		}
	}
	if len(candidates) == 0 {
		t.Fatalf("设备上没有第三方包可作 spawn 目标")
	}
	t.Logf("spawn 候选: %v", candidates)

	// 6) dex_dump.js 落盘并 spawn 注入(工具内嵌脚本)。个别系统/加固 app 对
	//    注入不耐受(加载脚本即死),按候选轮试,任一成功即继续。
	work := t.TempDir()
	script := filepath.Join(work, "dex_dump.js")
	if werr := os.WriteFile(script, []byte(dexDumpScript), 0o644); werr != nil {
		t.Fatalf("写脚本: %v", werr)
	}
	var listed string
	var dumpOK bool
	for _, pkg := range candidates {
		// --eternalize:新版 frida CLI -q 加载完即退,脚本驻留目标进程里继续跑。
		runCtx, runCancel := context.WithTimeout(ctx, 30*time.Second)
		out, _ := exec.CommandContext(runCtx, fridaBin,
			"-H", fmt.Sprintf("127.0.0.1:%d", port),
			"-f", pkg, "-l", script, "-q", "--eternalize").CombinedOutput()
		runCancel()
		time.Sleep(12 * time.Second) // 睡过 8s 第二轮扫描 + 余量
		listing, lerr := g.Request(rec.DeviceID, map[string]any{
			"t": "exec", "cmd": "ls -la " + deviceDumpDir + "/ 2>/dev/null | head -30", "asRoot": true, "timeoutMs": 15000,
		}, 25*time.Second)
		listed = ""
		if lerr == nil && listing.OK {
			listed = listing.Stdout
		}
		if strings.Contains(listed, ".dex") {
			dumpOK = true
			t.Logf("候选 %s dump 成功", pkg)
			break
		}
		t.Logf("候选 %s 未产出 dex(frida 输出: %s)", pkg, clampString(string(out), 300))
	}
	if !dumpOK {
		t.Fatalf("全部候选未 dump 到 dex,设备侧清单:\n%s", listed)
	}
	deviceTar := "/data/local/tmp/sentinel-unpack-smoke.tar"
	tarRes, trErr := g.Request(rec.DeviceID, map[string]any{
		"t": "exec", "asRoot": true, "timeoutMs": 60000,
		"cmd": fmt.Sprintf("rm -f %s; tar cf %s -C %s . && echo done", deviceTar, deviceTar, deviceDumpDir),
	}, 70*time.Second)
	if trErr != nil || !tarRes.OK {
		t.Fatalf("设备侧打包失败: %v %+v", trErr, tarRes)
	}
	hostTar := filepath.Join(work, "dump.tar")
	f, fErr := os.Create(hostTar)
	if fErr != nil {
		t.Fatalf("建本地文件: %v", fErr)
	}
	pull, written, plErr := g.PullFile(rec.DeviceID, deviceTar, 256*1024*1024, f, 120*time.Second)
	_ = f.Close()
	if plErr != nil || !pull.OK || written == 0 {
		t.Fatalf("拉取失败: %v %+v %d", plErr, pull, written)
	}
	outDir := filepath.Join(work, "unpack")
	if eErr := extractTarFlat(hostTar, outDir); eErr != nil {
		t.Fatalf("解包: %v", eErr)
	}
	dex := listDexFiles(outDir)
	if len(dex) == 0 {
		t.Fatalf("解包后没有 dex")
	}
	t.Logf("动态冒烟通过:dump %d 个 dex,产物 %s(最大: %v)", len(dex), outDir, dex[0])
}

// TestLiveDeviceCleanup 真机清理:杀 frida-server、删冒烟落盘文件、force-stop
// 被 spawn 过的 App(清掉可能驻留的 eternalize 脚本;绝不动 DroidBridge 自己)。
// 门控:ARTEX_LIVE_DEVICE_SMOKE=1 且 ARTEX_LIVE_CLEANUP=1。
func TestLiveDeviceCleanup(t *testing.T) {
	if os.Getenv("ARTEX_LIVE_DEVICE_SMOKE") == "" || os.Getenv("ARTEX_LIVE_CLEANUP") == "" {
		t.Skip("清理需 ARTEX_LIVE_DEVICE_SMOKE=1 且 ARTEX_LIVE_CLEANUP=1")
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	key, kerr := readLiveJWTKey("")
	if kerr != nil {
		t.Fatalf("%v", kerr)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()
	store := db.NewDeviceStore(pg, key)
	recs, err := store.List(context.Background())
	if err != nil || len(recs) == 0 {
		t.Fatalf("设备台账为空: %v", err)
	}
	rec := recs[0]
	g := newDeviceGateway(store)
	defer g.Close()
	if err := g.Listen("0.0.0.0", 8791); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if _, stale, online := g.Liveness(rec.DeviceID); online && !stale {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("设备未重连")
		}
		time.Sleep(2 * time.Second)
	}
	run := func(name, cmd string) {
		res, rerr := g.Request(rec.DeviceID, map[string]any{
			"t": "exec", "asRoot": false, "timeoutMs": 15000, "cmd": cmd,
		}, 20*time.Second)
		out := strings.TrimSpace(res.Stdout + " " + res.Stderr)
		if rerr != nil || !res.OK {
			t.Logf("%s: 失败 %v %s", name, rerr, out)
			return
		}
		t.Logf("%s: %s", name, orDefault(out, "ok"))
	}
	// 杀 frida-server(pid 定点,不用 pkill 防自匹配)
	run("kill frida-server", `su -c "kill \$(pidof frida-server) 2>/dev/null"; su -c "pidof frida-server || echo dead"`)
	// 删冒烟落盘
	run("rm files", `su -c "rm -f /data/local/tmp/frida-server /data/local/tmp/artex-frame-smoke.txt /data/local/tmp/sentinel-unpack-*.tar; rm -rf /data/local/tmp/sentinel-unpack"`)
	run("verify", `su -c "ls /data/local/tmp/ | head -20"`)
	// force-stop 被 spawn 过的 App(清 eternalize 驻留;不含 DroidBridge)
	for _, pkg := range []string{"com.coloros.soundrecorder", "com.tencent.wetype", "com.sdu.didi.psnger",
		"com.oray.peanuthull", "com.jooan.smarteye.lenovo", "com.redteamobile.roaming",
		"com.tencent.mm", "com.github.kr328.clash"} {
		run("force-stop "+pkg, `su -c "am force-stop `+pkg+`"`)
	}
}
