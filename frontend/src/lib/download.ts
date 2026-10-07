import { getToken } from "@/api/client";

/** Authenticated download/open for report endpoints (plain links would not carry the bearer token). */
export async function openAuthed(path: string, filename?: string) {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  if (filename) {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
  } else {
    window.open(url, "_blank", "noopener");
  }
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
