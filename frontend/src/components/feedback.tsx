import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { X } from "lucide-react";
import { ApiError } from "@/api/client";
import { Button, cx } from "./ui";
import type { Tone } from "@/lib/format";
import { TONE_SOFT } from "@/lib/format";

interface Toast { id: number; tone: Tone; title: string; detail?: string }
const ToastCtx = createContext<(t: Omit<Toast, "id">) => void>(() => undefined);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev.slice(-3), { ...t, id }]);
    window.setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), t.tone === "crit" ? 9000 : 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={cx("pointer-events-auto rounded border bg-panel px-3 py-2 shadow-lg", TONE_SOFT[t.tone])}>
            <div className="flex items-start justify-between gap-2">
              <p className="text-sm font-semibold">{t.title}</p>
              <button aria-label="Dismiss" onClick={() => setToasts((p) => p.filter((x) => x.id !== t.id))}><X className="h-3.5 w-3.5" /></button>
            </div>
            {t.detail && <p className="mt-0.5 text-xs text-ink/80">{t.detail}</p>}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/** Wrap an API call: success/error toast and a busy flag. 403s surface the server's RBAC message. */
export function useAction() {
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const run = useCallback(async <T,>(key: string, fn: () => Promise<T>, success?: string | ((r: T) => string)): Promise<T | undefined> => {
    setBusy(key);
    try {
      const r = await fn();
      if (success) toast({ tone: "ok", title: typeof success === "function" ? success(r) : success });
      return r;
    } catch (e) {
      const err = e instanceof ApiError ? e : new ApiError(0, String(e));
      toast({ tone: err.status === 403 ? "warn" : "crit", title: err.status === 403 ? "Not permitted" : "Action failed", detail: err.detail });
      return undefined;
    } finally {
      setBusy(null);
    }
  }, [toast]);
  return { run, busy };
}

/** Native <dialog> (top layer, focus trap, Esc). closedby="any" for light-dismiss with a click fallback. */
export function Dialog({ open, onClose, title, children, footer, drawer, wide }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; drawer?: boolean; wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  useEffect(() => {
    const d = ref.current;
    if (!d || "closedBy" in HTMLDialogElement.prototype) return;
    const onClick = (e: MouseEvent) => {
      if (e.target !== d) return;
      const r = d.getBoundingClientRect();
      if (e.clientY < r.top || e.clientY > r.bottom || e.clientX < r.left || e.clientX > r.right) d.close();
    };
    d.addEventListener("click", onClick);
    return () => d.removeEventListener("click", onClick);
  }, []);
  return (
    <dialog ref={ref} onClose={onClose} {...({ closedby: "any" } as object)} aria-label={typeof title === "string" ? title : undefined}
      className={cx("bg-panel p-0 text-ink shadow-2xl", drawer ? "drawer" : cx("rounded-md border border-line", wide ? "w-[min(920px,94vw)]" : "w-[min(560px,94vw)]"))}>
      {open && (
        <div className={cx("flex flex-col", drawer ? "h-full" : "max-h-[85vh]")}>
          <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
            <h2 className="font-cond text-lg font-semibold leading-6">{title}</h2>
            <button className="rounded p-1 text-muted hover:bg-inset hover:text-ink" aria-label="Close" onClick={onClose}><X className="h-4 w-4" /></button>
          </header>
          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">{children}</div>
          {footer && <footer className="flex justify-end gap-2 border-t border-line px-4 py-3">{footer}</footer>}
        </div>
      )}
    </dialog>
  );
}

export function ConfirmButton({ label, confirmTitle, confirmText, onConfirm, variant = "secondary", icon, busy, disabled, size }: {
  label: string; confirmTitle: string; confirmText: ReactNode; onConfirm: () => void | Promise<unknown>; variant?: "primary" | "secondary" | "danger" | "auto";
  icon?: ReactNode; busy?: boolean; disabled?: boolean; size?: "sm" | "md";
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant={variant} icon={icon} loading={busy} disabled={disabled} size={size} onClick={() => setOpen(true)}>{label}</Button>
      <Dialog open={open} onClose={() => setOpen(false)} title={confirmTitle}
        footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant={variant === "secondary" ? "primary" : variant} onClick={async () => { setOpen(false); await onConfirm(); }}>{label}</Button></>}>
        <div className="text-sm">{confirmText}</div>
      </Dialog>
    </>
  );
}
