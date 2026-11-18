import type { Request, Response, NextFunction } from "express";
import type { Role } from "../types/index.js";
import { writeAudit } from "../utils/audit.js";

export function requireRole(...allowed: Role[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ ok: false, error: "Not authenticated" });
      return;
    }
    if (!allowed.includes(user.role)) {
      void writeAudit({
        userId: user.id,
        username: user.username,
        action: "role_denied",
        status: "failure",
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        details: { required: allowed, actual: user.role, path: req.path },
      });
      res.status(403).json({ ok: false, error: "Forbidden: role not allowed" });
      return;
    }
    next();
  };
}
