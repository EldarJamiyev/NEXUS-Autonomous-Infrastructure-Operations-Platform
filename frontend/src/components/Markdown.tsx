import type { ReactNode } from "react";

function inline(text: string): ReactNode[] {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((p, i) => p.startsWith("`") ? <code key={i} className="rounded bg-inset px-1 font-mono text-[12px]">{p.slice(1, -1)}</code>
    : p.startsWith("**") ? <strong key={i}>{p.slice(2, -2)}</strong> : <span key={i}>{p}</span>);
}

/** Minimal Markdown renderer for NEXUS-generated reports (headings, lists, tables, quotes, code). */
export function Markdown({ text }: { text: string }) {
  const out: ReactNode[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("|")) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        const cells = lines[i].replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
        if (!cells.every((c) => /^[-: ]*$/.test(c))) rows.push(cells);
        i++;
      }
      i--;
      out.push(
        <div key={i} className="my-3 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-inset text-xs text-muted"><tr>{rows[0].map((c, k) => <th key={k} className="px-2 py-1 font-medium">{inline(c)}</th>)}</tr></thead>
          <tbody>{rows.slice(1).map((r, k) => <tr key={k} className="border-t border-line align-top">{r.map((c, j) => <td key={j} className="px-2 py-1">{inline(c)}</td>)}</tr>)}</tbody></table></div>,
      );
    } else if (line.startsWith("- ")) {
      const items: string[] = [];
      while (i < lines.length && lines[i].startsWith("- ")) items.push(lines[i++].slice(2));
      i--;
      out.push(<ul key={i} className="my-2 list-disc space-y-0.5 pl-5 text-sm">{items.map((t, k) => <li key={k}>{inline(t)}</li>)}</ul>);
    } else if (line.startsWith("### ")) out.push(<h4 key={i} className="mt-4 font-cond text-[15px] font-semibold">{inline(line.slice(4))}</h4>);
    else if (line.startsWith("## ")) out.push(<h3 key={i} className="mt-5 border-b border-line pb-1 font-cond text-lg font-semibold">{inline(line.slice(3))}</h3>);
    else if (line.startsWith("# ")) out.push(<h2 key={i} className="font-cond text-2xl font-semibold">{inline(line.slice(2))}</h2>);
    else if (line.startsWith("> ")) out.push(<blockquote key={i} className="my-2 border-l-2 border-accent pl-3 text-sm text-muted">{inline(line.slice(2))}</blockquote>);
    else if (line.trim()) out.push(<p key={i} className="my-1.5 text-sm leading-6">{inline(line)}</p>);
  }
  return <div>{out}</div>;
}
