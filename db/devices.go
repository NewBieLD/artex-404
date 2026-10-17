// devices.go 是 Android 反连设备的落库层(schema.sql §N,判活期 1)。
// 仿 sessions.go:token 明文只出现在 Enroll/RevealToken 返回值里,库里存
// sha256(token) 供反连鉴权 O(1) 查表 + AES-GCM 密文供设备页重显(域分离
// 标签 artex/devices/v1,与 sessions/credentials 互不通用)。
package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// DeviceRecord 是 devices 表的一行(不含 token 密文)。
type DeviceRecord struct {
	ID             int64     `json:"id"`
	DeviceID       string    `json:"device_id"` // DroidBridge APK 自生成,首次 hello 绑定
	Name           string    `json:"name"`
	Model          string    `json:"model"`
	AndroidVersion string    `json:"android_version"`
	SdkInt         int       `json:"sdk_int"`
	Rooted         bool      `json:"rooted"`
	Status         string    `json:"status"` // online | offline
	NodeID         int64     `json:"node_id"`
	LastSeen       time.Time `json:"last_seen"`
	CreatedAt      time.Time `json:"created_at"`
}

const (
	DeviceOnline  = "online"
	DeviceOffline = "offline"
)

// DeviceSecretKey 由 master key(jwt.key)派生设备 token 加密密钥:与 sessions/
// credentials 各自域分离。
func DeviceSecretKey(master []byte) []byte {
	sum := sha256.Sum256(append([]byte("artex/devices/v1\x00"), master...))
	return sum[:]
}

// DeviceStore 是 devices 表的访问层(加密件与 SessionStore 同一套 gcm1: 格式)。
type DeviceStore struct {
	d   *DB
	key []byte
}

func NewDeviceStore(d *DB, masterKey []byte) *DeviceStore {
	var key []byte
	if len(masterKey) > 0 {
		key = DeviceSecretKey(masterKey)
	}
	return &DeviceStore{d: d, key: key}
}

func (s *DeviceStore) encryptToken(token string) (string, error) {
	if len(s.key) != 32 {
		return "", fmt.Errorf("设备 token 加密密钥未初始化,拒绝明文落库")
	}
	gcm, err := newGCM(s.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(token), nil)
	return secretPrefix + hex.EncodeToString(sealed), nil
}

func (s *DeviceStore) decryptToken(stored string) (string, error) {
	if len(s.key) != 32 {
		return "", fmt.Errorf("设备 token 加密密钥未初始化,无法解密")
	}
	if !hasPrefix(stored, secretPrefix) {
		return "", fmt.Errorf("未知 token 密文格式(缺 gcm1: 前缀)")
	}
	raw, err := hex.DecodeString(stored[len(secretPrefix):])
	if err != nil {
		return "", fmt.Errorf("token 密文 hex 解码失败: %w", err)
	}
	gcm, err := newGCM(s.key)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("token 密文过短")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("token 解密失败(密钥不符或数据被篡改): %w", err)
	}
	return string(plain), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Enroll 登记一台设备:生成 24 字节随机 token(hex 48 字符),返回记录与
// token 明文(仅此一次返回;重显走 RevealToken)。name 可空。
func (s *DeviceStore) Enroll(ctx context.Context, name string) (*DeviceRecord, string, error) {
	raw := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, "", err
	}
	token := hex.EncodeToString(raw)
	enc, err := s.encryptToken(token)
	if err != nil {
		return nil, "", err
	}
	rec := &DeviceRecord{Name: name, Status: DeviceOffline}
	err = s.d.QueryRowContext(ctx, `
INSERT INTO devices(name, token_hash, token_enc, status)
VALUES ($1, $2, $3, 'offline')
RETURNING id, created_at, last_seen`,
		name, tokenHash(token), enc).Scan(&rec.ID, &rec.CreatedAt, &rec.LastSeen)
	if err != nil {
		return nil, "", err
	}
	return rec, token, nil
}

const deviceCols = `id, device_id, name, model, android_version, sdk_int, rooted, status,
	node_id, last_seen, created_at`

func scanDevice(row interface{ Scan(...any) error }) (*DeviceRecord, error) {
	var r DeviceRecord
	if err := row.Scan(&r.ID, &r.DeviceID, &r.Name, &r.Model, &r.AndroidVersion, &r.SdkInt,
		&r.Rooted, &r.Status, &r.NodeID, &r.LastSeen, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// List 取全部(按 id 升序)。
func (s *DeviceStore) List(ctx context.Context) ([]*DeviceRecord, error) {
	rows, err := s.d.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DeviceRecord{}
	for rows.Next() {
		r, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get 取一条;不存在返回 (nil, nil)。
func (s *DeviceStore) Get(ctx context.Context, id int64) (*DeviceRecord, error) {
	r, err := scanDevice(s.d.QueryRowContext(ctx,
		`SELECT `+deviceCols+` FROM devices WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// FindByToken 反连鉴权查表:sha256(token) 命中返回对应行;查无返回 (nil, nil)。
func (s *DeviceStore) FindByToken(ctx context.Context, token string) (*DeviceRecord, error) {
	r, err := scanDevice(s.d.QueryRowContext(ctx,
		`SELECT `+deviceCols+` FROM devices WHERE token_hash=$1`, tokenHash(token)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// RevealToken 解密设备 token(设备页重显连接参数用)。
func (s *DeviceStore) RevealToken(ctx context.Context, id int64) (string, error) {
	var enc string
	err := s.d.QueryRowContext(ctx, `SELECT token_enc FROM devices WHERE id=$1`, id).Scan(&enc)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("设备 %d 不存在", id)
	}
	if err != nil {
		return "", err
	}
	return s.decryptToken(enc)
}

// BindOnHello 首次 hello:把 deviceId 与设备指纹绑定到 token 行并标 online。
// device_id 已被别的登记占用时返回错误(token 复用/换绑的诚实信号)。
func (s *DeviceStore) BindOnHello(ctx context.Context, id int64, deviceID, model, androidVersion string, sdkInt int, rooted bool) error {
	tag, err := s.d.ExecContext(ctx, `
UPDATE devices SET device_id=$2, model=$3, android_version=$4, sdk_int=$5, rooted=$6,
	status='online', last_seen=now()
WHERE id=$1 AND ($2 = '' OR device_id = '' OR device_id = $2)`,
		id, deviceID, model, androidVersion, sdkInt, rooted)
	if err != nil {
		return err
	}
	// token 行已绑了别的 deviceId(device_id<>'' 且不等于 $2):UPDATE 0 行。
	if n, _ := tag.RowsAffected(); n == 0 {
		var bound string
		_ = s.d.QueryRowContext(ctx, `SELECT device_id FROM devices WHERE id=$1`, id).Scan(&bound)
		return fmt.Errorf("该登记 token 已绑定设备 %q,拒绝换绑(一台设备一个 token)", bound)
	}
	return nil
}

// TouchSeen 刷新 last_seen(心跳/任意帧到达时;fire-and-forget 语义,错误只回给调用方日志)。
func (s *DeviceStore) TouchSeen(ctx context.Context, id int64) error {
	_, err := s.d.ExecContext(ctx,
		`UPDATE devices SET last_seen=now(), status='online' WHERE id=$1`, id)
	return err
}

// SetStatus 更新 online/offline(离线/删除前踢线)。
func (s *DeviceStore) SetStatus(ctx context.Context, id int64, status string) error {
	if status != DeviceOnline && status != DeviceOffline {
		return fmt.Errorf("非法设备状态 %q(online|offline)", status)
	}
	_, err := s.d.ExecContext(ctx, `UPDATE devices SET status=$2 WHERE id=$1`, id, status)
	return err
}

// MarkAllOffline 启动诚实化:平台重启 = 所有设备断连,DB 全量标 offline
// (与 initReverse 把上期 reverse 会话标 dead 同一取向,不装活)。
func (s *DeviceStore) MarkAllOffline(ctx context.Context) (int64, error) {
	tag, err := s.d.ExecContext(ctx,
		`UPDATE devices SET status='offline' WHERE status='online'`)
	if err != nil {
		return 0, err
	}
	n, _ := tag.RowsAffected()
	return n, nil
}

// Delete 删除一条(调用方先踢线)。
func (s *DeviceStore) Delete(ctx context.Context, id int64) error {
	_, err := s.d.ExecContext(ctx, `DELETE FROM devices WHERE id=$1`, id)
	return err
}
