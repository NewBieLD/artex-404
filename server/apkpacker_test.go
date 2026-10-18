package server

// apkpacker_test.go:加固识别(detectPacker)与 droid_unpack 辅助函数的单测。
// 特征表与全链哨兵 11ee8e99 的 PACKER_SIGNATURES 对齐,命中/未命中/三种
// 输入形态(目录、apk zip、单 dex)各覆盖一路。

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTB(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectPackerDirHitJiagu(t *testing.T) {
	dir := t.TempDir()
	writeTB(t, filepath.Join(dir, "lib/arm64-v8a/libjiagu_x.so"), "MZ fake so")
	writeTB(t, filepath.Join(dir, "smali/com/stub/StubApp.smali"), ".class public Lcom/stub/StubApp;")
	hardened, hits, soFiles, _, err := detectPacker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hardened {
		t.Fatalf("期望命中 360 加固,hits=%v so=%v", hits, soFiles)
	}
	found := false
	for _, h := range hits {
		if strings.Contains(h.Vendor, "360") {
			found = true
		}
	}
	if !found {
		t.Fatalf("命中列表里没有 360: %v", hits)
	}
}

func TestDetectPackerDirClean(t *testing.T) {
	dir := t.TempDir()
	writeTB(t, filepath.Join(dir, "lib/arm64-v8a/libnative-lib.so"), "plain")
	writeTB(t, filepath.Join(dir, "smali/com/example/MainActivity.smali"), ".class public Lcom/example/MainActivity;")
	hardened, hits, _, _, err := detectPacker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hardened {
		t.Fatalf("干净样本误报: %v", hits)
	}
}

func TestDetectPackerApkZipHitBangcle(t *testing.T) {
	apk := filepath.Join(t.TempDir(), "sample.apk")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("lib/arm64-v8a/libDexHelper.so")
	_, _ = w.Write([]byte("bangcle"))
	w2, _ := zw.Create("classes.dex")
	_, _ = w2.Write([]byte("dex\n035 pretend, contains com.secneo.apkwrapper.StubApp"))
	_ = zw.Close()
	if err := os.WriteFile(apk, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	hardened, hits, _, _, err := detectPacker(apk)
	if err != nil {
		t.Fatal(err)
	}
	if !hardened {
		t.Fatalf("期望命中梆梆: hits=%v", hits)
	}
	hitBangcle := false
	for _, h := range hits {
		if strings.Contains(h.Vendor, "梆梆") {
			hitBangcle = true
		}
	}
	if !hitBangcle {
		t.Fatalf("命中列表里没有梆梆: %v", hits)
	}
}

func TestDetectPackerDexFileHitLegu(t *testing.T) {
	dex := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(dex, []byte("garbage com.tencent.StubShell garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	hardened, hits, _, _, err := detectPacker(dex)
	if err != nil {
		t.Fatal(err)
	}
	if !hardened {
		t.Fatalf("期望命中腾讯乐固: hits=%v", hits)
	}
}

func TestExtractTarFlatAndSanitize(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "dump.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	_ = tw.WriteHeader(&tar.Header{Name: "classes_1.dex", Mode: 0o644, Size: int64(len("dex1"))})
	_, _ = tw.Write([]byte("dex1"))
	_ = tw.WriteHeader(&tar.Header{Name: "../evil.dex", Mode: 0o644, Size: 4})
	_, _ = tw.Write([]byte("evil"))
	_ = tw.Close()
	_ = f.Close()

	out := filepath.Join(dir, "out")
	if err := extractTarFlat(tarPath, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "classes_1.dex"))
	if err != nil || string(data) != "dex1" {
		t.Fatalf("常规条目未解出: %v %q", err, data)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil.dex")); !os.IsNotExist(err) {
		t.Fatalf("路径穿越条目未被拒绝")
	}
	if got := sanitizeFileName("com.target.app/../x"); got != "com.target.app..x" {
		t.Fatalf("sanitizeFileName 意外: %q", got)
	}
}
