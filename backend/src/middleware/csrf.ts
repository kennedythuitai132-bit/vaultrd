import type { Request, Response, NextFunction } from "express";
import { randomToken } from "../utils/crypto.js";

const COOKIE = "vaultrd_csrf";
const HEADER = "x-csrf-token";

export function issueCsrfToken(req: Request, res: Response): string {
  let token = req.cookies?.[COOKIE];
  if (typeof token !== "string" || token.length < 32) {
    token = randomToken(24);
    res.cookie(COOKIE, token, {
      httpOnly: false,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 2 * 60 * 60 * 1000,
    });
  }
  return token;
}

export function verifyCsrf(req: Request, res: Response, next: NextFunction): void {
  const method = req.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    next();
    return;
  }
  const cookieToken = req.cookies?.[COOKIE];
  const headerToken = req.headers[HEADER];
  if (
    typeof cookieToken !== "string" ||
    typeof headerToken !== "string" ||
    cookieToken.length < 32 ||
    cookieToken !== headerToken
  ) {
    res.status(403).json({ ok: false, error: "CSRF check failed" });
    return;
  }
  next();
}
