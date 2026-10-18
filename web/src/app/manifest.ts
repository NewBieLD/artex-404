import type { MetadataRoute } from "next";

// PWA manifest:添加到主屏后全屏运行(standalone),手机遥控场景当原生 App 用。
// 不含 service worker(无离线承诺);图标由 public/logo.png 派生。
// output:export 下元数据路由必须显式 force-static。
export const dynamic = "force-static";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "ARTEX",
    short_name: "ARTEX",
    description: "AI 自主渗透测试系统",
    start_url: "/dashboard",
    display: "standalone",
    orientation: "any",
    background_color: "#0a0a0a",
    theme_color: "#0a0a0a",
    icons: [
      { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
      { src: "/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
  };
}
