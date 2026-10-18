// droidunpack.go 是 droid_unpack host 工具:加固 APK 的内存脱壳管道
// (移植自全链哨兵 11ee8e99 的 droid_unpack,形态对齐 deviceTools 家族)。
// 管道:确保设备侧 frida-server 存活 → 网关开 TCP 隧道(本机随机端口 ↔
// 设备 127.0.0.1:27042)→ 宿主机 frida CLI spawn 目标 app 注入内嵌
// dex_dump.js(FRIDA-DEXDump 风格,两轮扫内存 dex magic)→ 设备侧 tar
// → 网关流式 pull → 本地解包到工作目录 evidence/unpack/<包名>/。
// 局限同哨兵:抽取壳(函数体 nop)dump 出的方法体仍是空的,需 FART 级
// 主动调用,超出本工具范围。
package server

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	deviceFridaServer = "/data/local/tmp/frida-server"
	deviceDumpDir     = "/data/local/tmp/sentinel-unpack" // dex_dump.js 内写死,与哨兵共用
	deviceFridaPort   = 27042
)

// dexDumpScript 源自哨兵 11ee8e99 的内建 dex_dump,有一处刻意偏离:去掉了
// Java.perform 包裹(Java 在其中只做 mkdir)。真机踩坑:frida 17.24.1 +
// Android 16(ColorOS)组合下,脚本加载期(spawn 门控中)执行 Java.perform 会
// 直接杀死会话("the connection is closed"),8/8 目标全灭;setTimeout 与纯
// gum 内存操作不受影响。目录预建的职责已上收到 ensureDeviceDumpDir(root
// 执行),脚本保持纯 gum、无 Java 依赖。
const dexDumpScript = `(function () {
  var SAVE_DIR = "/data/local/tmp/sentinel-unpack";
  var dumped = {};
  var count = 0;
  function dumpDex(addr) {
    try {
      var magic = new Uint8Array(Memory.readByteArray(addr, 4));
      if (magic[0] !== 0x64 || magic[1] !== 0x65 || magic[2] !== 0x78 || magic[3] !== 0x0a) return;
      var fileSize = Memory.readU32(addr.add(32));
      if (fileSize < 112 || fileSize > 120 * 1024 * 1024) return;
      var key = addr.toString() + ":" + fileSize;
      if (dumped[key]) return;
      dumped[key] = true;
      var path = SAVE_DIR + "/classes_" + addr.toString(16) + "_" + fileSize + ".dex";
      var f = new File(path, "wb");
      f.write(Memory.readByteArray(addr, fileSize));
      f.close();
      count++;
      console.log("[dexdump] saved " + path);
    } catch (e) {}
  }
  function scan() {
    var ranges = Process.enumerateRanges("r--").concat(Process.enumerateRanges("rw-"));
    ranges.forEach(function (range) {
      if (range.size < 112 || range.size > 120 * 1024 * 1024) return;
      try {
        Memory.scan(range.base, range.size, "64 65 78 0a 30 33", {
          onMatch: function (addr) { dumpDex(addr); },
          onComplete: function () {},
        });
      } catch (e) {}
    });
  }
  setTimeout(scan, 500);
  setTimeout(scan, 8000);
  setTimeout(function () { console.log("[dexdump] finished, " + count + " dex saved to " + SAVE_DIR); }, 9000);
})();`

// toolWorkDir 工具的工作目录基准:worker 调用时是任务目录,REST/测试回落
// 安装目录(与 runScriptTool 同款取向)。
func (s *Server) toolWorkDir(tc *actool.ToolContext) string {
	if tc != nil && tc.WorkingDir != "" {
		return tc.WorkingDir
	}
	return s.m.dir
}

// fridaCLIBin 解析宿主机 frida CLI:ARTEX_FRIDA_BIN 显式指定优先。
func fridaCLIBin() string {
	if p := strings.TrimSpace(os.Getenv("ARTEX_FRIDA_BIN")); p != "" {
		return p
	}
	if p, err := exec.LookPath("frida"); err == nil {
		return p
	}
	return ""
}

// ensureDeviceFridaServer 保证设备侧 frida-server 在跑:已在跑直接过;设备
// 上有二进制就拉起;都没有则用工作目录里的 frida-server 推过去再拉起(59MB
// 级二进制走网关分片 push)。返回失败时给可操作的指引。
func (s *Server) ensureDeviceFridaServer(rec *db.DeviceRecord, wd string) error {
	res, err := s.devGW.Request(rec.DeviceID, map[string]any{
		"t": "exec", "cmd": "pidof frida-server", "asRoot": false, "timeoutMs": 6000,
	}, 8*time.Second)
	if err == nil && res.OK && strings.TrimSpace(res.Stdout) != "" {
		return nil
	}
	// 设备上有没有二进制。
	have, herr := s.devGW.Request(rec.DeviceID, map[string]any{
		"t": "exec", "cmd": "ls /data/local/tmp/frida-server 2>/dev/null && echo FOUND", "asRoot": false, "timeoutMs": 6000,
	}, 8*time.Second)
	if herr != nil || !have.OK || !strings.Contains(have.Stdout, "FOUND") {
		hostBin := filepath.Join(wd, "frida-server")
		if _, serr := os.Stat(hostBin); serr != nil {
			return fmt.Errorf(
				"设备上没有 frida-server,工作目录也没有可推送的二进制(%s)。\n"+
					"请下载与宿主机 frida 版本匹配的 android-arm64 frida-server 放到工作目录(文件名 frida-server),"+
					"或手动 adb push 到设备 %s 后重试", hostBin, deviceFridaServer)
		}
		data, rerr := os.ReadFile(hostBin)
		if rerr != nil {
			return fmt.Errorf("读取 %s 失败: %v", hostBin, rerr)
		}
		push, perr := s.devGW.PushFile(rec.DeviceID, deviceFridaServer, data, "0755", 120*time.Second)
		if perr != nil || !push.OK {
			return fmt.Errorf("推送 frida-server 失败: %v %s", perr, push.Error)
		}
	}
	// 拉起。注意 DroidBridge exec 以 app 身份(untrusted_app)跑:SELinux 拒绝
	// app 对 /data/local/tmp 的 chmod,root 进程也不在 app 可见的 /proc 里——
	// chmod/启动/查 pid 必须整段走 su(真机踩坑:非 su 的 chmod 直接 EACCES)。
	start, serr := s.devGW.Request(rec.DeviceID, map[string]any{
		"t": "exec", "asRoot": false, "timeoutMs": 20000,
		"cmd": fmt.Sprintf(`su -c "chmod 755 %s; nohup %s > /dev/null 2>&1 &"; sleep 1; su -c "pidof frida-server"`,
			deviceFridaServer, deviceFridaServer),
	}, 25*time.Second)
	if serr != nil || !start.OK {
		return fmt.Errorf("frida-server 启动失败: %v %s(设备需 root)", serr, start.Error)
	}
	if strings.TrimSpace(start.Stdout) == "" {
		return fmt.Errorf("frida-server 启动后 pidof 为空(设备可能无 root 或 su 拒绝)")
	}
	return nil
}

// ensureDeviceDumpDir root 预建脱壳产物目录并放开权限(dex_dump 以 app 进程
// 身份落盘,untrusted_app 写不了未放开的 /data/local/tmp 子目录)。
func (s *Server) ensureDeviceDumpDir(deviceID string) error {
	res, err := s.devGW.Request(deviceID, map[string]any{
		"t": "exec", "asRoot": true, "timeoutMs": 8000,
		"cmd": "mkdir -p " + deviceDumpDir + " && chmod 0777 " + deviceDumpDir + " && echo OK",
	}, 12*time.Second)
	if err != nil || !res.OK {
		return fmt.Errorf("脱壳目录准备失败: %v %s", err, res.Error)
	}
	return nil
}

// droidUnpackTool 内存脱壳 host 工具(默认绑 worker)。
func (s *Server) droidUnpackTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "droid_unpack",
		Description: "内存脱壳加固 APK:spawn 目标 app 注入 dex_dump(FRIDA-DEXDump 风格),等壳解密后扫进程内存里的 dex magic," +
			"dump 出的 dex 打包拉回并解到工作目录 evidence/unpack/<包名>/。前置:root 设备在线、设备侧 frida-server" +
			"(没有会尝试用工作目录 frida-server 推送拉起)、宿主机 frida CLI(pip install frida-tools)。返回 dex 清单与路径," +
			"后续用反编译工具逐个看最大的几个 dex。局限:抽取壳(函数体 nop)dump 出的方法体仍是空的。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"device_id": strParam("list_devices 返回的 device_id(或行 id)"),
				"app":       strParam("目标应用包名(spawn 模式启动,如 com.target.app)"),
				"seconds":   map[string]any{"type": "integer", "description": "等待收集秒数(默认 30,范围 10-120;越晚加载的 dex 越多)"},
			},
			"required": []any{"device_id", "app"},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: devicePerm,
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				DeviceID string `json:"device_id"`
				App      string `json:"app"`
				Seconds  int    `json:"seconds"`
			}
			_ = json.Unmarshal(in, &a)
			a.App = strings.TrimSpace(a.App)
			if a.App == "" {
				return actool.Errorf("app 必填(目标应用包名)"), nil
			}
			rec, err := s.lookupDevice(a.DeviceID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Seconds < 10 {
				a.Seconds = 30
			}
			if a.Seconds > 120 {
				a.Seconds = 120
			}
			wd := s.toolWorkDir(tc)
			fridaBin := fridaCLIBin()
			if fridaBin == "" {
				return actool.Errorf("宿主机没有 frida CLI:请 pip install frida-tools,或用环境变量 ARTEX_FRIDA_BIN 指定路径"), nil
			}
			if !rec.Rooted {
				return actool.Errorf(fmt.Sprintf("设备 %s 未 root,内存脱壳需要 root 设备", rec.Name)), nil
			}
			if err := s.ensureDeviceFridaServer(rec, wd); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// dex_dump 以 app 进程身份写 /data/local/tmp/sentinel-unpack,
			// untrusted_app 对 /data/local/tmp 无写权限——root 预建并放开目录。
			if mkErr := s.ensureDeviceDumpDir(rec.DeviceID); mkErr != nil {
				return actool.Errorf(mkErr.Error()), nil
			}
			port, terr := s.devGW.OpenTunnel(rec.DeviceID, "127.0.0.1", deviceFridaPort)
			if terr != nil {
				return actool.Errorf("隧道建立失败: " + terr.Error()), nil
			}
			// 内嵌 dex_dump 落到工作目录(与哨兵一致的布局)。
			fridaDir := filepath.Join(wd, "frida")
			if mkErr := os.MkdirAll(fridaDir, 0o755); mkErr != nil {
				return actool.Errorf("创建目录失败: " + mkErr.Error()), nil
			}
			scriptPath := filepath.Join(fridaDir, "dex_dump.js")
			if wErr := os.WriteFile(scriptPath, []byte(dexDumpScript), 0o644); wErr != nil {
				return actool.Errorf("写入 dex_dump.js 失败: " + wErr.Error()), nil
			}

			// frida CLI -q 在加载完脚本后即退出(新版行为,与哨兵容器内老版不同):
			// --eternalize 让脚本驻留目标进程,CLI 退出后 0.5s/8s 两轮扫描继续跑,
			// 这里睡满采集窗口再收割。
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(runCtx, fridaBin,
				"-H", fmt.Sprintf("127.0.0.1:%d", port),
				"-f", a.App, "-l", scriptPath, "-q", "--eternalize")
			out, _ := cmd.CombinedOutput()
			fridaOut := clampString(string(out), 4000)
			select {
			case <-ctx.Done():
				return actool.Errorf("上下文取消"), nil
			case <-time.After(time.Duration(a.Seconds) * time.Second):
			}

			listing, lerr := s.devGW.Request(rec.DeviceID, map[string]any{
				"t": "exec", "cmd": "ls -la " + deviceDumpDir + "/ 2>/dev/null | head -50", "asRoot": true, "timeoutMs": 15000,
			}, 25*time.Second)
			listed := ""
			if lerr == nil && listing.OK {
				listed = listing.Stdout
			}
			if !strings.Contains(listed, ".dex") {
				return actool.Errorf(
					"未 dump 到任何 dex。frida 输出:\n"+orDefault(fridaOut, "(无输出)")+
						"\n排查:app 是否被杀(先在技能资产里用 anti_frida_bypass);"+
						"壳是否把解密 dex 放到只执行内存(该工具覆盖不了)"), nil
			}
			dexCount := strings.Count(listed, ".dex")
			pack := sanitizeFileName(a.App)
			deviceTar := fmt.Sprintf("/data/local/tmp/sentinel-unpack-%s.tar", pack)

			tarRes, trErr := s.devGW.Request(rec.DeviceID, map[string]any{
				"t": "exec", "asRoot": true, "timeoutMs": 60000,
				"cmd": fmt.Sprintf("rm -f %s; tar cf %s -C %s . && echo done", deviceTar, deviceTar, deviceDumpDir),
			}, 70*time.Second)
			if trErr != nil || !tarRes.OK {
				return actool.Errorf(fmt.Sprintf("设备侧打包失败: %v %s", trErr, tarRes.Error)), nil
			}

			hostTar := filepath.Join(wd, "evidence", "unpack", pack+".tar")
			if mkErr := os.MkdirAll(filepath.Dir(hostTar), 0o755); mkErr != nil {
				return actool.Errorf("创建目录失败: " + mkErr.Error()), nil
			}
			f, fErr := os.Create(hostTar)
			if fErr != nil {
				return actool.Errorf("创建本地文件失败: " + fErr.Error()), nil
			}
			pull, written, pErr := s.devGW.PullFile(rec.DeviceID, deviceTar, 256*1024*1024, f, 120*time.Second)
			_ = f.Close()
			if pErr != nil || !pull.OK || written == 0 {
				_ = os.Remove(hostTar)
				return actool.Errorf(fmt.Sprintf("拉取失败: %v %s", pErr, pull.Error)), nil
			}


			outDir := filepath.Join(wd, "evidence", "unpack", pack)
			if exErr := extractTarFlat(hostTar, outDir); exErr != nil {
				return actool.Errorf("解包失败: " + exErr.Error()), nil
			}
			dexFiles := listDexFiles(outDir)
			return jsonResult(map[string]any{
				"ok": true, "device": rec.Name, "app": a.App, "dex_count": dexCount,
				"path": outDir, "tar": hostTar, "tar_bytes": written,
				"dex_files": dexFiles, "device_listing": clampString(listed, 2000),
				"hint": "脱壳完成;下一步逐个反编译最大的几个 dex(jadx/apk_decompile),直接反编译 base.apk 只会得到壳代码",
			})
		},
	})
}

// extractTarFlat 把 tar 解到 outDir(仅常规文件与目录,拒绝路径穿越)。
func extractTarFlat(tarPath, outDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}
		target := filepath.Join(outDir, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, oErr := os.Create(target)
			if oErr != nil {
				return oErr
			}
			if _, cErr := io.Copy(out, tr); cErr != nil {
				_ = out.Close()
				return cErr
			}
			_ = out.Close()
		}
	}
	return nil
}

// listDexFiles 列出解包目录里的 dex(按大小降序,最大者优先反编译)。
func listDexFiles(dir string) []map[string]any {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []map[string]any
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dex") {
			continue
		}
		info, iErr := e.Info()
		if iErr != nil {
			continue
		}
		files = append(files, map[string]any{"name": e.Name(), "bytes": info.Size()})
	}
	// 简单按大小降序。
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j]["bytes"].(int64) > files[i]["bytes"].(int64) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	if len(files) > 20 {
		files = files[:20]
	}
	return files
}

// sanitizeFileName 把包名变成安全的文件名段。
func sanitizeFileName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "app"
	}
	return b.String()
}

func clampString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…[截断]"
}
