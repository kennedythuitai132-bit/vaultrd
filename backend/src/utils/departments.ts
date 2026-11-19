import { query } from "../config/db.js";

export async function getUserDepartmentIds(userId: number): Promise<number[]> {
  const { rows } = await query<{ department_id: number | string }>(
    "SELECT department_id FROM user_departments WHERE user_id = $1",
    [userId]
  );
  return rows.map((r) => Number(r.department_id));
}

export type DeptResolution =
  | { ok: true; departmentId: number | null }
  | { ok: false; status: number; error: string };

// Decides which department a new file/grant belongs to.
export async function resolveDepartment(
  user: { id: number; role: string },
  requested: unknown
): Promise<DeptResolution> {
  const ids = await getUserDepartmentIds(user.id);
  const reqId = Number(requested);
  const hasRequested =
    requested !== undefined && requested !== null && requested !== "" && Number.isInteger(reqId) && reqId > 0;

  if (hasRequested) {
    if (user.role === "admin") {
      const d = await query("SELECT id FROM departments WHERE id = $1", [reqId]);
      if (!d.rows[0]) return { ok: false, status: 400, error: "Department not found" };
      return { ok: true, departmentId: reqId };
    }
    if (!ids.includes(reqId)) return { ok: false, status: 403, error: "You do not belong to that department" };
    return { ok: true, departmentId: reqId };
  }

  const first = ids[0];
  if (first !== undefined) return { ok: true, departmentId: first };
  if (user.role === "admin") return { ok: true, departmentId: null };
  return { ok: false, status: 403, error: "You are not assigned to a department. Ask an admin." };
}