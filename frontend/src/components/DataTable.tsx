import { useMemo, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, Search } from "lucide-react";
import { Button, Empty, cx, inputClass } from "./ui";

export interface Column<T> { key: string; header: string; render?: (row: T) => ReactNode; sort?: (row: T) => string | number; className?: string; search?: (row: T) => string }

export function DataTable<T>({ rows, columns, rowKey, onRowClick, searchable = true, pageSize = 25, empty = "No records", placeholder = "Filter", toolbar, selected }: {
  rows: T[]; columns: Column<T>[]; rowKey: (r: T) => string; onRowClick?: (r: T) => void; searchable?: boolean; pageSize?: number; empty?: string; placeholder?: string;
  toolbar?: ReactNode; selected?: string | null;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [page, setPage] = useState(0);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let out = needle ? rows.filter((r) => columns.some((c) => (c.search ? c.search(r) : String((r as any)[c.key] ?? "")).toLowerCase().includes(needle))) : rows;
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      const get = col?.sort ?? ((r: T) => (r as any)[sort.key]);
      out = [...out].sort((a, b) => (get(a) > get(b) ? 1 : get(a) < get(b) ? -1 : 0) * sort.dir);
    }
    return out;
  }, [rows, q, sort, columns]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages - 1);
  const slice = filtered.slice(current * pageSize, current * pageSize + pageSize);
  return (
    <div className="min-w-0">
      {(searchable || toolbar) && (
        <div className="mb-2 flex flex-wrap items-center gap-2">
          {searchable && (
            <label className="relative">
              <Search className="pointer-events-none absolute left-2 top-2 h-4 w-4 text-muted" />
              <input value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} placeholder={placeholder} aria-label={placeholder} className={cx(inputClass, "w-56 pl-7")} />
            </label>
          )}
          {toolbar}
          <span className="ml-auto text-xs text-muted">{filtered.length} of {rows.length}</span>
        </div>
      )}
      <div className="overflow-x-auto rounded border border-line">
        <table className="w-full border-separate border-spacing-0 text-left text-sm">
          <thead className="sticky top-0 z-[1] bg-inset">
            <tr>{columns.map((c) => (
              <th key={c.key} scope="col" className={cx("whitespace-nowrap border-b border-line px-3 py-2 text-xs font-medium text-muted", c.className)}>
                <button className="inline-flex items-center gap-1 hover:text-ink" onClick={() => setSort(sort?.key === c.key ? { key: c.key, dir: (sort.dir * -1) as 1 | -1 } : { key: c.key, dir: 1 })}>
                  {c.header}{sort?.key === c.key && (sort.dir === 1 ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
                </button>
              </th>
            ))}</tr>
          </thead>
          <tbody>
            {slice.map((r) => {
              const key = rowKey(r);
              return (
                <tr key={key} onClick={onRowClick ? () => onRowClick(r) : undefined} tabIndex={onRowClick ? 0 : undefined}
                  onKeyDown={onRowClick ? (e) => { if (e.key === "Enter") onRowClick(r); } : undefined}
                  className={cx(onRowClick && "cursor-pointer hover:bg-inset", selected === key && "bg-accent/10")}>
                  {columns.map((c) => <td key={c.key} className={cx("border-b border-line px-3 py-1.5 align-middle", c.className)}>{c.render ? c.render(r) : String((r as any)[c.key] ?? "-")}</td>)}
                </tr>
              );
            })}
          </tbody>
        </table>
        {!slice.length && <div className="p-3"><Empty title={empty} /></div>}
      </div>
      {pages > 1 && (
        <div className="mt-2 flex items-center justify-end gap-2 text-xs text-muted">
          <Button size="sm" disabled={current === 0} onClick={() => setPage(current - 1)}>Previous</Button>
          <span>Page {current + 1} / {pages}</span>
          <Button size="sm" disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>Next</Button>
        </div>
      )}
    </div>
  );
}
