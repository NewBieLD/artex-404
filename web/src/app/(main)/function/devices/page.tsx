"use client";

// 设备页(判活期 1):Android 反连设备台账 + 登记(token 一次性展示)、
// 人工判活、token 重显、删除、反连监听起/重绑。10s 轮询刷新运行态。

import * as React from "react";

import {
  ActivityIcon,
  CopyIcon,
  KeyRoundIcon,
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  SmartphoneIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { DeviceListenInfo, DroidDevice } from "@/lib/types";
import { cn } from "@/lib/utils";

const DEVICES_POLL_MS = 10_000;

function fmtTime(iso: string): string {
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return "—";
  return t.toLocaleString("zh-CN", { hour12: false });
}

function fmtIdle(ms?: number): string {
  if (ms === undefined) return "";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${Math.round(ms / 3_600_000)}h`;
}
// 三态:在线(心跳正常)/ 无响应(连接在但 45s 无帧)/ 离线。
function StateBadge({ state }: { state: string }) {
  if (state === "online") {
    return (
      <Badge variant="secondary" className="gap-1.5 text-xs text-emerald-600">
        <span className="size-1.5 rounded-full bg-emerald-500" />
        在线
      </Badge>
    );
  }
  if (state === "unresponsive") {
    return (
      <Badge variant="secondary" className="gap-1.5 text-xs text-amber-600">
        <span className="size-1.5 rounded-full bg-amber-500" />
        无响应
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="gap-1.5 text-xs text-muted-foreground">
      <span className="size-1.5 rounded-full bg-neutral-400" />
      离线
    </Badge>
  );
}

function CopyLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-16 shrink-0 text-xs text-muted-foreground">{label}</span>
      {/* break-all 换行展示:token 48 字符、扫码内容带 ?token= 更长,截断会误抄。 */}
      <code className="min-w-0 flex-1 rounded bg-muted px-2 py-1 font-mono text-xs break-all">{value}</code>
      <Button
        variant="outline"
        size="icon"
        className="size-7 shrink-0"
        title="复制"
        onClick={() => {
          navigator.clipboard.writeText(value).then(
            () => toast.success(`${label} 已复制`),
            () => toast.error("复制失败"),
          );
        }}
      >
        <CopyIcon className="size-3.5" />
      </Button>
    </div>
  );
}

// 接入二维码:每次挂载换一张(ticket 一次性),内容 = 接入地址?token=。
function QRBlock({ deviceId }: { deviceId: number }) {
  const [src, setSrc] = React.useState("");
  React.useEffect(() => {
    let alive = true;
    setSrc("");
    api
      .deviceQRSrc(deviceId)
      .then((s) => {
        if (alive) setSrc(s);
      })
      .catch(() => {
        /* 二维码拉取失败只缺图,文案通道仍可用 */
      });
    return () => {
      alive = false;
    };
  }, [deviceId]);
  return (
    <div className="flex flex-col items-center gap-1.5">
      {src ? (
        // biome-ignore lint/performance/noImgElement: 一次性 ticket src,Next/Image 缓存层反而会吃掉它
        <img src={src} alt="接入二维码" className="size-52 rounded-md border bg-white p-2" />
      ) : (
        <div className="flex size-52 items-center justify-center rounded-md border">
          <Loader2Icon className="size-5 animate-spin text-muted-foreground" />
        </div>
      )}
      <span className="text-center text-xs text-muted-foreground">
        手机 DroidBridge →「扫码填入」对准此码,接入地址与 token 自动填入
      </span>
    </div>
  );
}

export default function DevicesPage() {
  const [devices, setDevices] = React.useState<DroidDevice[]>([]);
  const [listen, setListen] = React.useState<DeviceListenInfo | null>(null);
  const [wsURL, setWsURL] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  const [enrollOpen, setEnrollOpen] = React.useState(false);
  const [enrollName, setEnrollName] = React.useState("");
  const [enrolling, setEnrolling] = React.useState(false);
  const [enrolled, setEnrolled] = React.useState<{ id: number; token: string; ws_url: string } | null>(null);

  const [revealed, setRevealed] = React.useState<DroidDevice | null>(null);
  const [revealToken, setRevealToken] = React.useState("");
  const [revealing, setRevealing] = React.useState(false);

  const [pendingDelete, setPendingDelete] = React.useState<DroidDevice | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [probingId, setProbingId] = React.useState<number | null>(null);

  const [listenHost, setListenHost] = React.useState("0.0.0.0");
  const [listenPort, setListenPort] = React.useState("8791");
  const [binding, setBinding] = React.useState(false);

  const load = React.useCallback((initial = false) => {
    if (initial) setLoading(true);
    api
      .devices()
      .then((r) => {
        setDevices(r.items);
        setListen(r.listen);
        setWsURL(r.ws_url);
      })
      .catch(() => {
        /* 保留上一次数据 */
      })
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    load(true);
    const timer = setInterval(() => load(), DEVICES_POLL_MS);
    return () => clearInterval(timer);
  }, [load]);

  const enroll = () => {
    setEnrolling(true);
    api
      .deviceEnroll(enrollName.trim())
      .then((r) => {
        setEnrolled({ id: r.id, token: r.token, ws_url: r.ws_url });
        setEnrollName("");
        load();
      })
      .catch((e: unknown) => toast.error(e instanceof Error ? e.message : "登记失败"))
      .finally(() => setEnrolling(false));
  };

  const reveal = (d: DroidDevice) => {
    setRevealing(true);
    api
      .deviceReveal(d.id)
      .then((r) => {
        setRevealed(d);
        setRevealToken(r.token);
      })
      .catch((e: unknown) => toast.error(e instanceof Error ? e.message : "token 读取失败"))
      .finally(() => setRevealing(false));
  };

  const probe = (d: DroidDevice) => {
    setProbingId(d.id);
    api
      .deviceProbe(d.id)
      .then((r) => {
        if (r.alive) {
          toast.success(`${d.name || d.device_id || `#${d.id}`} 探活成功(${r.ms}ms):${r.stdout || "ok"}`);
        } else {
          toast.error(`${d.name || d.device_id || `#${d.id}`} 探活失败:${r.error ?? "未知原因"}`);
        }
      })
      .catch((e: unknown) => toast.error(e instanceof Error ? e.message : "探活失败"))
      .finally(() => {
        setProbingId(null);
        load();
      });
  };

  const confirmDelete = () => {
    const target = pendingDelete;
    if (!target) return;
    setDeleting(true);
    api
      .deviceDelete(target.id)
      .then(() => {
        toast.success(`设备 #${target.id} 已删除`);
        setPendingDelete(null);
        load();
      })
      .catch((e: unknown) => toast.error(e instanceof Error ? e.message : "删除失败"))
      .finally(() => setDeleting(false));
  };

  const applyListen = () => {
    const port = Number.parseInt(listenPort, 10);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      toast.error(`端口非法:${listenPort}`);
      return;
    }
    setBinding(true);
    api
      .deviceListenSet(listenHost.trim() || "127.0.0.1", port)
      .then((r) => {
        toast.success(`反连监听已绑定 ${r.host}:${r.port}`);
        load();
      })
      .catch((e: unknown) => toast.error(e instanceof Error ? e.message : "绑定失败"))
      .finally(() => setBinding(false));
  };

  const onlineCount = devices.filter((d) => d.state === "online").length;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <SmartphoneIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">设备</h1>
          <Badge variant="secondary" className="tabular-nums">
            在线 {onlineCount}/{devices.length}
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="h-8 gap-1" onClick={() => setEnrollOpen(true)}>
            <PlusIcon className="size-3.5" />
            登记设备
          </Button>
          <Button variant="outline" size="sm" className="h-8 gap-1" onClick={() => load(true)}>
            <RefreshCwIcon className={cn("size-3.5", loading && "animate-spin")} />
            刷新
          </Button>
        </div>
      </div>

      {/* 反连监听 */}
      <Card className="py-4">
        <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-3 px-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">反连监听</span>
            {listen?.enabled ? (
              <Badge variant="secondary" className="font-mono text-xs">
                {listen.host}:{listen.port}
              </Badge>
            ) : (
              <Badge variant="outline" className="text-xs text-muted-foreground">
                未启动
              </Badge>
            )}
          </div>
          {wsURL && (
            <div className="flex min-w-0 items-center gap-2">
              <span className="text-sm text-muted-foreground">接入地址</span>
              <code className="truncate rounded bg-muted px-2 py-1 font-mono text-xs" title={wsURL}>
                {wsURL}
              </code>
            </div>
          )}
          <div className="ml-auto flex items-center gap-2">
            <Input
              value={listenHost}
              onChange={(e) => setListenHost(e.target.value)}
              className="h-8 w-28 font-mono text-xs"
              placeholder="0.0.0.0"
              title="监听网卡 IP(手机接入用 0.0.0.0 或网卡 IP)"
            />
            <Input
              value={listenPort}
              onChange={(e) => setListenPort(e.target.value)}
              className="h-8 w-20 font-mono text-xs"
              placeholder="8791"
            />
            <Button variant="outline" size="sm" className="h-8" disabled={binding} onClick={applyListen}>
              {binding ? <Loader2Icon className="size-3.5 animate-spin" /> : null}
              绑定
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 台账 */}
      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
        <div className="min-h-0 flex-1 overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <TableHead className="w-[60px]">ID</TableHead>
                <TableHead className="w-[120px]">名称</TableHead>
                <TableHead className="w-[160px]">deviceId</TableHead>
                <TableHead>机型</TableHead>
                <TableHead className="w-[70px]">root</TableHead>
                <TableHead className="w-[100px]">状态</TableHead>
                <TableHead className="w-[170px]">最近心跳</TableHead>
                <TableHead className="w-[240px]">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && devices.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-12 text-center">
                    <Loader2Icon className="mx-auto h-5 w-5 animate-spin text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ) : devices.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-12 text-center text-sm text-muted-foreground">
                    暂无设备。点「登记设备」生成 token,把接入地址与 token 填进手机 DroidBridge。
                  </TableCell>
                </TableRow>
              ) : (
                devices.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">#{d.id}</TableCell>
                    <TableCell className="max-w-0 truncate" title={d.name}>
                      {d.name || "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs" title={d.device_id}>
                      {d.device_id ? (
                        <span className="block truncate">{d.device_id}</span>
                      ) : (
                        <span className="text-muted-foreground">未接入</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="truncate text-xs">{d.model || "—"}</span>
                        {d.android_version && (
                          <span className="text-[10px] text-muted-foreground">
                            Android {d.android_version}
                            {d.sdk_int ? ` (SDK ${d.sdk_int})` : ""}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {d.rooted ? (
                        <Badge variant="secondary" className="text-xs">
                          root
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <StateBadge state={d.state} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground tabular-nums">
                      <div className="flex flex-col">
                        <span>{fmtTime(d.last_seen)}</span>
                        {d.online && d.idle_ms !== undefined && (
                          <span className="text-[10px]">空闲 {fmtIdle(d.idle_ms)}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 gap-1"
                          title="经反连通道执行 id 探活(5s 超时)"
                          disabled={probingId === d.id || !d.device_id}
                          onClick={() => probe(d)}
                        >
                          {probingId === d.id ? (
                            <Loader2Icon className="size-3.5 animate-spin" />
                          ) : (
                            <ActivityIcon className="size-3.5" />
                          )}
                          探活
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 gap-1"
                          title="重显接入 token"
                          disabled={revealing}
                          onClick={() => reveal(d)}
                        >
                          <KeyRoundIcon className="size-3.5" />
                          token
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7 text-muted-foreground hover:text-red-600"
                          title="删除设备(踢线并移除登记)"
                          onClick={() => setPendingDelete(d)}
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </Card>

      {/* 登记弹窗:token 仅此一次明文展示 */}
      <Dialog
        open={enrollOpen}
        onOpenChange={(o) => {
          if (!o) {
            setEnrollOpen(false);
            setEnrolled(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>登记设备</DialogTitle>
            <DialogDescription>
              生成接入 token。把接入地址与 token 填进手机 DroidBridge(Server URL / Token), deviceId 由 App
              生成、首次连接自动绑定到本登记。
            </DialogDescription>
          </DialogHeader>
          {enrolled ? (
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
              <div className="flex min-w-0 flex-1 flex-col gap-2">
                <CopyLine label="接入地址" value={enrolled.ws_url} />
                <CopyLine label="token" value={enrolled.token} />
                <CopyLine label="扫码内容" value={`${enrolled.ws_url}?token=${enrolled.token}`} />
                <p className="text-xs text-muted-foreground">
                  token 也可随时从台账「token」按钮重显。一台设备一个 token,换机请重新登记。
                </p>
              </div>
              <div className="shrink-0 self-center">
                <QRBlock deviceId={enrolled.id} />
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <Label htmlFor="device-name">设备名称(可选)</Label>
              <Input
                id="device-name"
                value={enrollName}
                onChange={(e) => setEnrollName(e.target.value)}
                placeholder="如:OnePlus 测试机"
              />
            </div>
          )}
          <DialogFooter>
            {enrolled ? (
              <Button
                onClick={() => {
                  setEnrollOpen(false);
                  setEnrolled(null);
                }}
              >
                完成
              </Button>
            ) : (
              <Button disabled={enrolling} onClick={enroll}>
                {enrolling ? <Loader2Icon className="size-4 animate-spin" /> : null}
                生成 token
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* token 重显 */}
      <Dialog open={revealed !== null} onOpenChange={(o) => !o && setRevealed(null)}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              #{revealed?.id} {revealed?.name || ""} 的接入 token
            </DialogTitle>
            <DialogDescription>填进 DroidBridge 的 Token 字段;接入地址用页首展示值。</DialogDescription>
          </DialogHeader>
          {revealToken && revealed && (
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
              <div className="flex min-w-0 flex-1 flex-col gap-2">
                <CopyLine label="token" value={revealToken} />
                {wsURL && <CopyLine label="接入地址" value={wsURL} />}
                {wsURL && <CopyLine label="扫码内容" value={`${wsURL}?token=${revealToken}`} />}
              </div>
              <div className="shrink-0 self-center">
                <QRBlock deviceId={revealed.id} />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setRevealed(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={pendingDelete !== null} onOpenChange={(o) => !o && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除设备 #{pendingDelete?.id}?</AlertDialogTitle>
            <AlertDialogDescription>
              将断开连接并移除登记({pendingDelete?.name || pendingDelete?.device_id || "未接入"}), 手机上的 DroidBridge
              不受影响,但该 token 立即失效。此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(e) => {
                e.preventDefault();
                confirmDelete();
              }}
            >
              {deleting ? "删除中…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
