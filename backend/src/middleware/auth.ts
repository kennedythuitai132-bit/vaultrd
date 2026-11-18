import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../utils/jwt.js";
import type { AuthUser, JwtPayload } from "../types/index.js";
import { query } from "../config/db.js";

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

function readToken(req: Request): string | null {
  const cookie = req.cookies?.["vaultrd_token"];
  if (typeof cookie === "string" && cookie.length > 0) return cookie;
  const auth = req.headers.authorization;
  if (typeof auth === "string" && auth.startsWith("Bearer ")) {
    return auth.slice(7);
  }
  return null;
}

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const token = readToken(req);
  if (!token) {
    res.status(401).json({ ok: false, error: "Not authenticated" });
    return;
  }
  let payload: JwtPayload;
  try {
    payload = verifyAccessToken(token);
  } catch {
    res.status(401).json({ ok: false, error: "Invalid or expired token" });
    return;
  }
  const { rows } = await query<{
    id: number;
    username: string;
    email: string;
    full_name: string;
    role: "admin" | "researcher" | "viewer";
    is_active: boolean;
    is_approved: boolean;
  }>(
    "SELECT id, username, email, full_name, role, is_active, is_approved FROM users WHERE id = $1",
    [payload.sub]
  );
  const u = rows[0];
  if (!u || !u.is_active) {
    res.status(401).json({ ok: false, error: "Account inactive" });
    return;
  }
  req.user = {
    id: u.id,
    username: u.username,
    email: u.email,
    full_name: u.full_name,
    role: u.role,
    is_active: u.is_active,
    is_approved: u.is_approved,
  };
  next();
}
