import { query } from "../config/db.js";
import { getUserDepartmentIds } from "./departments.js";

export type FileAccess = "ok" | "notfound" | "forbidden";

// admin: any file. others: files in their departments (files with no department stay owner-only).
export async function checkFileAccess(user: { id: number; role: string }, fileId: number): Promise<FileAccess> {
  const { rows } = await query<{ owner_id: number | string; department_id: number | string | null }>(
    "SELECT owner_id, department_id FROM research_files WHERE id = $1 AND is_deleted = FALSE",
    [fileId]
  );
  const f = rows[0];
  if (!f) return "notfound";
  if (user.role === "admin") return "ok";
  if (f.department_id !== null && f.department_id !== undefined) {
    const ids = await getUserDepartmentIds(user.id);
    return ids.includes(Number(f.department_id)) ? "ok" : "forbidden";
  }
  return Number(f.owner_id) === user.id ? "ok" : "forbidden";
}