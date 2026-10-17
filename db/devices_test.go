package db

// devices_test.go:devices 落库层测试。token 加解密 roundtrip 不依赖 PG;
// CRUD/绑定语义走现有 PG-gated skip 模式(无库即跳)。

import (
	"context"
	"strings"
	"testing"
)

// TestDeviceTokenCrypto 不依赖 PG:AES-GCM roundtrip、密钥域分离、
// 未初始化密钥拒绝、篡改密文认证失败。
func TestDeviceTokenCrypto(t *testing.T) {
	master := []byte("test-jwt-key-material-32bytes!!!")
	if string(DeviceSecretKey(master)) == string(SessionSecretKey(master)) {
		t.Fatal("devices 与 sessions 派生密钥必须域分离")
	}
	store := &DeviceStore{key: DeviceSecretKey(master)}
	enc, err := store.encryptToken("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
	if err != nil {
		t.Fatalf("encryptToken: %v", err)
	}
	if !strings.HasPrefix(enc, secretPrefix) || strings.Contains(enc, "a1b2c3d4") {
		t.Fatalf("token 密文格式错误: %q", enc[:16])
	}
	dec, err := store.decryptToken(enc)
	if err != nil || dec != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" {
		t.Fatalf("decryptToken: %q %v", dec, err)
	}
	tampered := enc[:len(enc)-4] + "AAAA"
	if _, err := store.decryptToken(tampered); err == nil {
		t.Fatal("篡改密文应认证失败")
	}
	if _, err := (&DeviceStore{}).encryptToken("x"); err == nil {
		t.Fatal("未初始化密钥应拒绝加密")
	}
	if h1, h2 := tokenHash("abc"), tokenHash("abd"); h1 == h2 || len(h1) != 64 {
		t.Fatalf("tokenHash 输出异常: %q %q", h1, h2)
	}
}

// TestDeviceStoreCRUD 走 live PG(skip 模式):Enroll → FindByToken →
// BindOnHello(首绑/换绑拒绝)→ TouchSeen → SetStatus → MarkAllOffline →
// RevealToken → Delete。
func TestDeviceStoreCRUD(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	store := NewDeviceStore(d, []byte("test-jwt-key-material-32bytes!!!"))
	ctx := context.Background()

	rec, token, err := store.Enroll(ctx, "测试机")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// defer 而非 t.Cleanup:defer d.Close() 在测试体内,Cleanup 会撞上已关的池。
	defer func() { _ = store.Delete(context.Background(), rec.ID) }()
	if len(token) != 48 {
		t.Fatalf("token 应为 24 字节 hex(48 字符),got %d", len(token))
	}

	// 落库不得含 token 明文。
	var rawHash, rawEnc string
	if err := d.QueryRow(`SELECT token_hash, token_enc FROM devices WHERE id=$1`, rec.ID).
		Scan(&rawHash, &rawEnc); err != nil {
		t.Fatal(err)
	}
	if rawHash != tokenHash(token) || strings.Contains(rawEnc, token) {
		t.Fatal("token 落库应为 sha256 + gcm1 密文")
	}

	// token 鉴权查表。
	got, err := store.FindByToken(ctx, token)
	if err != nil || got == nil || got.ID != rec.ID {
		t.Fatalf("FindByToken: %+v %v", got, err)
	}
	if bad, err := store.FindByToken(ctx, strings.Repeat("0", 48)); err != nil || bad != nil {
		t.Fatalf("假 token 不应命中: %+v %v", bad, err)
	}

	// 首次 hello 绑定 deviceId + 指纹 + online。
	if err := store.BindOnHello(ctx, rec.ID, "opus-1", "OnePlus 9", "14", 34, true); err != nil {
		t.Fatalf("BindOnHello: %v", err)
	}
	got, _ = store.Get(ctx, rec.ID)
	if got.DeviceID != "opus-1" || got.Model != "OnePlus 9" || !got.Rooted ||
		got.Status != DeviceOnline || got.AndroidVersion != "14" {
		t.Fatalf("绑定后行 = %+v", got)
	}
	// 同一 deviceId 重复 hello(重连)幂等刷新。
	if err := store.BindOnHello(ctx, rec.ID, "opus-1", "OnePlus 9", "14", 34, true); err != nil {
		t.Fatalf("重连绑定应幂等: %v", err)
	}

	// 换绑另一 deviceId 必须拒绝。
	if err := store.BindOnHello(ctx, rec.ID, "hijack", "x", "1", 1, false); err == nil {
		t.Fatal("换绑 deviceId 应被拒绝")
	}

	_ = store.TouchSeen(ctx, rec.ID)
	if err := store.SetStatus(ctx, rec.ID, DeviceOffline); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if n, err := store.MarkAllOffline(ctx); err != nil || n != 0 {
		t.Fatalf("MarkAllOffline(已全离线)应 0 行: %d %v", n, err)
	}

	// token 重显。
	revealed, err := store.RevealToken(ctx, rec.ID)
	if err != nil || revealed != token {
		t.Fatalf("RevealToken: %q %v", revealed, err)
	}

	if err := store.Delete(ctx, rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if gone, _ := store.Get(ctx, rec.ID); gone != nil {
		t.Fatal("删除后不应再查到")
	}
}
