"use client";

import * as React from "react";

import { LayoutTemplateIcon, PlusIcon, RefreshCwIcon, SaveIcon, SearchIcon, Trash2Icon } from "lucide-react";
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
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { TaskTemplate } from "@/lib/types";
import { cn } from "@/lib/utils";

const NAME_MAX = 120;
const TEXT_MAX = 16000;

interface TemplateDraft {
  name: string;
  description: string;
  goal: string;
}

const emptyDraft = (): TemplateDraft => ({ name: "", description: "", goal: "" });

function draftOf(template: TaskTemplate): TemplateDraft {
  return { name: template.name, description: template.description, goal: template.goal };
}

// 本地时间格式；秒级精度便于分辨"刚改过的模板"。
function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function TaskTemplatesPage() {
  const [templates, setTemplates] = React.useState<TaskTemplate[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [selectedID, setSelectedID] = React.useState<number | null>(null);
  const [draft, setDraft] = React.useState<TemplateDraft>(emptyDraft);
  const [query, setQuery] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.taskTemplates();
      setTemplates(list);
      setSelectedID((current) => {
        if (current != null && list.some((template) => template.id === current)) return current;
        return list[0]?.id ?? null;
      });
    } catch (error) {
      setTemplates([]);
      toast.error(`加载模板失败：${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 选中项变化（含首屏加载、删除后回退）时同步编辑区，避免草稿停留在已删除/旧模板上。
  const selected = React.useMemo(
    () => templates.find((template) => template.id === selectedID) ?? null,
    [selectedID, templates],
  );
  React.useEffect(() => {
    if (selected) setDraft(draftOf(selected));
  }, [selected]);

  const filtered = React.useMemo(() => {
    const keyword = query.trim().toLowerCase();
    if (!keyword) return templates;
    return templates.filter(
      (template) =>
        template.name.toLowerCase().includes(keyword) ||
        template.description.toLowerCase().includes(keyword) ||
        template.goal.toLowerCase().includes(keyword),
    );
  }, [query, templates]);

  const startNew = () => {
    setSelectedID(null);
    setDraft(emptyDraft());
  };

  const selectTemplate = (template: TaskTemplate) => {
    setSelectedID(template.id);
    setDraft(draftOf(template));
  };

  const dirty = React.useMemo(() => {
    if (!selected) return draft.name.trim() !== "" || draft.description.trim() !== "" || draft.goal.trim() !== "";
    return draft.name !== selected.name || draft.description !== selected.description || draft.goal !== selected.goal;
  }, [draft, selected]);

  const updateDraft = (field: keyof TemplateDraft, value: string) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };

  async function save() {
    const input = {
      name: draft.name.trim(),
      description: draft.description.trim(),
      goal: draft.goal.trim(),
    };
    if (!input.name || !input.description || !input.goal) {
      toast.error("请填写模板名称、描述和目标");
      return;
    }
    setSaving(true);
    try {
      if (selectedID == null) {
        const created = await api.createTaskTemplate(input);
        setTemplates((current) => [created, ...current]);
        setSelectedID(created.id);
        toast.success("模板已创建");
      } else {
        const updated = await api.updateTaskTemplate(selectedID, input);
        setTemplates((current) => [updated, ...current.filter((item) => item.id !== updated.id)]);
        toast.success("模板已更新");
      }
    } catch (error) {
      toast.error(`保存失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    if (selectedID == null) return;
    const deletedID = selectedID;
    setDeleting(true);
    try {
      await api.deleteTaskTemplate(deletedID);
      const remaining = templates.filter((template) => template.id !== deletedID);
      setTemplates(remaining);
      setSelectedID(remaining[0]?.id ?? null);
      if (!remaining[0]) setDraft(emptyDraft());
      setDeleteOpen(false);
      toast.success("模板已删除");
    } catch (error) {
      toast.error(`删除失败：${(error as Error).message}`);
    } finally {
      setDeleting(false);
    }
  }

  let saveLabel = "保存修改";
  if (saving) saveLabel = "保存中";
  else if (selectedID == null) saveLabel = "创建模板";

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <LayoutTemplateIcon className="size-5 text-muted-foreground" />
          <h1 className="font-semibold text-xl tracking-tight">任务模板</h1>
          <Badge variant="secondary">{templates.length}</Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" disabled={loading} onClick={() => void load()}>
            {loading ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon data-icon="inline-start" />}
            刷新
          </Button>
          <Button size="sm" onClick={startNew}>
            <PlusIcon data-icon="inline-start" />
            新建模板
          </Button>
        </div>
      </div>

      <Card className="min-h-0 flex-1 overflow-hidden py-0">
        <CardContent className="grid h-full min-h-[32rem] grid-cols-1 gap-0 p-0 lg:grid-cols-[20rem_minmax(0,1fr)]">
          <div className="flex min-h-0 flex-col border-b lg:border-r lg:border-b-0">
            <div className="relative border-b p-3">
              <SearchIcon className="absolute top-1/2 left-5.5 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="h-8 pl-8"
                placeholder="搜索名称 / 描述 / 目标"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
            <ScrollArea className="min-h-0 flex-1">
              <div className="flex flex-col gap-1 p-2">
                {loading && templates.length === 0 && (
                  <p className="px-2 py-6 text-center text-muted-foreground text-sm">正在加载模板</p>
                )}
                {!loading && templates.length === 0 && (
                  <p className="px-2 py-6 text-center text-muted-foreground text-sm">暂无模板，点击「新建模板」创建</p>
                )}
                {!loading && templates.length > 0 && filtered.length === 0 && (
                  <p className="px-2 py-6 text-center text-muted-foreground text-sm">没有匹配的模板</p>
                )}
                {filtered.map((template) => (
                  <button
                    key={template.id}
                    type="button"
                    className={cn(
                      "min-w-0 rounded-md px-2.5 py-2 text-left transition-colors",
                      selectedID === template.id ? "bg-accent text-accent-foreground" : "hover:bg-accent/50",
                    )}
                    onClick={() => selectTemplate(template)}
                  >
                    <span className="block truncate font-medium text-sm">{template.name}</span>
                    <span className="line-clamp-2 text-muted-foreground text-xs">{template.description}</span>
                    <span className="mt-1 block text-[10px] text-muted-foreground/80 tabular-nums">
                      更新于 {fmtTime(template.updated_at)}
                    </span>
                  </button>
                ))}
              </div>
            </ScrollArea>
          </div>

          <ScrollArea className="min-h-0">
            <div className="flex flex-col gap-4 p-6">
              {!loading && templates.length === 0 && selectedID == null ? (
                <Empty className="border">
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <LayoutTemplateIcon />
                    </EmptyMedia>
                    <EmptyTitle>还没有任务模板</EmptyTitle>
                    <EmptyDescription>
                      模板只保存描述与目标；创建任务时可直接套用，也可把当前填写的内容另存为模板。
                    </EmptyDescription>
                  </EmptyHeader>
                </Empty>
              ) : null}

              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="template-name">模板名称</FieldLabel>
                  <Input
                    id="template-name"
                    value={draft.name}
                    maxLength={NAME_MAX}
                    placeholder="例如：外部 Web 渗透测试"
                    onChange={(event) => updateDraft("name", event.target.value)}
                  />
                  <FieldDescription>名称唯一，用于创建任务时检索；最长 {NAME_MAX} 字符。</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="template-description">描述</FieldLabel>
                  <Textarea
                    id="template-description"
                    className="min-h-40"
                    value={draft.description}
                    maxLength={TEXT_MAX}
                    placeholder="测试对象、背景与约束，例如：目标为互联网暴露的 Web 应用，黑盒无账号"
                    onChange={(event) => updateDraft("description", event.target.value)}
                  />
                  <FieldDescription>会填进创建任务的「描述」，建议写明目标、类型与约束。</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="template-goal">目标</FieldLabel>
                  <Textarea
                    id="template-goal"
                    className="min-h-40"
                    value={draft.goal}
                    maxLength={TEXT_MAX}
                    placeholder="任务需要达成的可验证结果"
                    onChange={(event) => updateDraft("goal", event.target.value)}
                  />
                  <FieldDescription>会填进创建任务的「目标」；模板与已创建任务不保持关联。</FieldDescription>
                </Field>
              </FieldGroup>

              <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-4">
                <div className="flex items-center gap-2">
                  {selectedID != null && (
                    <Button type="button" variant="destructive" onClick={() => setDeleteOpen(true)}>
                      <Trash2Icon data-icon="inline-start" />
                      删除模板
                    </Button>
                  )}
                  {dirty && <span className="text-muted-foreground text-xs">有未保存的修改</span>}
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    disabled={!dirty || saving}
                    onClick={() => (selected ? setDraft(draftOf(selected)) : setDraft(emptyDraft()))}
                  >
                    放弃修改
                  </Button>
                  <Button type="button" disabled={saving} onClick={() => void save()}>
                    {saving ? <Spinner data-icon="inline-start" /> : <SaveIcon data-icon="inline-start" />}
                    {saveLabel}
                  </Button>
                </div>
              </div>
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除模板「{selected?.name || draft.name || "未命名模板"}」？</AlertDialogTitle>
            <AlertDialogDescription>已由该模板创建的任务不会受到影响。</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault();
                void remove();
              }}
            >
              {deleting && <Spinner data-icon="inline-start" />}
              {deleting ? "删除中" : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
