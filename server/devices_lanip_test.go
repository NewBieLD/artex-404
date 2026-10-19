package server

import (
	"net"
	"testing"
)

func cidrAddr(t *testing.T, s string) net.Addr {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR %s: %v", s, err)
	}
	return &net.IPNet{IP: ip, Mask: ipNet.Mask}
}

// WSL2 的 DNS 隧道地址 10.255.255.254/32 挂在 lo 上:地址本身非 127/8,
// 只有按接口跳过 FlagLoopback 才能排除。
func TestLanIPv4OfSkipsLoopbackInterface(t *testing.T) {
	addrs := []net.Addr{cidrAddr(t, "127.0.0.1/8"), cidrAddr(t, "10.255.255.254/32")}
	if got := lanIPv4Of(net.FlagLoopback|net.FlagUp, addrs); got != "" {
		t.Fatalf("回环接口上的地址未被跳过: %s", got)
	}
}

func TestLanIPv4OfPicksFirstUsable(t *testing.T) {
	addrs := []net.Addr{cidrAddr(t, "fe80::42:f7ff:fe6d:8343/64"), cidrAddr(t, "172.25.16.37/20")}
	if got := lanIPv4Of(net.FlagUp|net.FlagRunning, addrs); got != "172.25.16.37" {
		t.Fatalf("got %s, want 172.25.16.37", got)
	}
}

func TestLanIPv4OfSkipsDownAndLinkLocal(t *testing.T) {
	if got := lanIPv4Of(0, []net.Addr{cidrAddr(t, "192.168.3.89/24")}); got != "" {
		t.Fatalf("未启用接口应跳过: %s", got)
	}
	if got := lanIPv4Of(net.FlagUp, []net.Addr{cidrAddr(t, "169.254.100.7/16")}); got != "" {
		t.Fatalf("link-local 应跳过: %s", got)
	}
}
