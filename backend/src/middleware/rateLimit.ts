import rateLimit from "express-rate-limit";
import { env } from "../config/env.js";

export const loginLimiter = rateLimit({
  windowMs: env.loginWindowMinutes * 60 * 1000,
  limit: env.loginMaxAttempts,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { ok: false, error: "Too many login attempts, try later" },
  keyGenerator: (req) => {
    const body = (req.body ?? {}) as { username?: string };
    return String(req.ip ?? "unknown") + "|" + String(body.username ?? "");
  },
  validate: false,
});
