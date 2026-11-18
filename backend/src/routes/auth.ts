import { Router, type Request, type Response } from "express";
import bcrypt from "bcrypt";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { query } from "../config/db.js";
import { env } from "../config/env.js";
import { logger } from "../utils/logger.js";
import { signAccessToken } from "../utils/jwt.js";
import { writeAudit, raiseAlert } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { issueCsrfToken } from "../middleware/csrf.js";
import { loginLimiter } from "../middleware/rateLimit.js";
import type { Role } from "../types/index.js";

export const authRouter = Router();

const TOKEN_COOKIE = "vaultrd_token";
const PENDING_COOKIE = "vaultrd_pending";
const MAX_FAILS_BEFORE_ALERT = 5;

function setTokenCookie(res: Response, token: string): void {
  res.cookie(TOKEN_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 2 * 60 * 60 * 1000,
    path: "/",
  });
}

function setPendingCookie(res: Response, userId: number): void {
  res.cookie(PENDING_COOKIE, String(userId), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 5 * 60 * 1000,
    path: "/",
  });
}

function clearAuthCookies(res: Response): void {
  res.clearCookie(TOKEN_COOKIE, { path: "/" });
  res.clearCookie(PENDING_COOKIE, { path: "/" });
}

interface UserRow {
  id: number;
  username: string;
  email: string;
  full_name: string;
  password_hash: string;
  role: Role;
  is_active: boolean;
  is_approved: boolean;
}

// ---------------- LOGIN (password step) ----------------
authRouter.post("/login", loginLimiter, async (req: Request, res: Response) => {
  const { username, password } = (req.body ?? {}) as { username?: string; password?: string };
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  issueCsrfToken(req, res);

  if (!username || !password) {
    res.status(400).json({ ok: false, error: "username and password required" });
    return;
  }

  const { rows } = await query<UserRow>(
    "SELECT id, username, email, full_name, password_hash, role, is_active, is_approved FROM users WHERE LOWER(username) = LOWER($1)",
    [username]
  );
  const user = rows[0];

  const recordAttempt = async (success: boolean, reason: string) => {
    await query(
      "INSERT INTO login_attempts (username, ip_address, success, reason) VALUES ($1, $2, $3, $4)",
      [username, ip ?? null, success, reason]
    );
    if (!success) {
      const { rows: cnt } = await query<{ n: string }>(
        "SELECT COUNT(*)::text AS n FROM login_attempts WHERE LOWER(username) = LOWER($1) AND success = FALSE AND attempted_at > NOW() - INTERVAL '15 minutes'",
        [username]
      );
      if (Number(cnt[0]?.n ?? "0") >= MAX_FAILS_BEFORE_ALERT) {
        await raiseAlert({
          alertType: "brute_force",
          severity: "high",
          title: "Repeated failed logins for user: " + username,
          relatedUser: username,
          ip,
          details: { failures_last_15min: Number(cnt[0]?.n ?? "0") },
        });
      }
    }
  };

  if (!user) {
    await recordAttempt(false, "unknown_user");
    await writeAudit({ username, action: "login_failed", status: "failure", ip, userAgent: ua, details: { reason: "unknown_user" } });
    res.status(401).json({ ok: false, error: "Invalid credentials" });
    return;
  }
  if (!user.is_active) {
    await recordAttempt(false, "inactive");
    await writeAudit({ userId: user.id, username: user.username, action: "login_failed", status: "failure", ip, userAgent: ua, details: { reason: "inactive" } });
    res.status(403).json({ ok: false, error: "Account is inactive" });
    return;
  }

  if (!user.is_approved) {
    await recordAttempt(false, "pending_approval");
    await writeAudit({ userId: user.id, username: user.username, action: "signup_rejected_login", status: "failure", ip, userAgent: ua, details: { reason: "pending_approval" } });
    res.status(403).json({ ok: false, error: "Your account is pending administrator approval." });
    return;
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    await recordAttempt(false, "wrong_password");
    await writeAudit({ userId: user.id, username: user.username, action: "login_failed", status: "failure", ip, userAgent: ua, details: { reason: "wrong_password" } });
    res.status(401).json({ ok: false, error: "Invalid credentials" });
    return;
  }

  await recordAttempt(true, "password_ok");

  const { rows: mfaRows } = await query<{ is_enabled: boolean }>(
    "SELECT is_enabled FROM mfa_secrets WHERE user_id = $1",
    [user.id]
  );
  const mfaEnabled = Boolean(mfaRows[0]?.is_enabled);

  setPendingCookie(res, user.id);

  if (mfaEnabled) {
    res.json({
      ok: true,
      requiresMfa: true,
      stage: "mfa_verify",
      next: "/api/auth/mfa/verify",
    });
    return;
  }

  // First-time MFA setup — generate secret + QR
  const secret = speakeasy.generateSecret({
    name: env.mfaIssuer + " (" + user.username + ")",
    issuer: env.mfaIssuer,
    length: 20,
  });
  await query(
    `INSERT INTO mfa_secrets (user_id, secret, is_enabled)
     VALUES ($1, $2, FALSE)
     ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret`,
    [user.id, secret.base32]
  );
  const otpauth = secret.otpauth_url ?? "";
  const qr = await qrcode.toDataURL(otpauth);
  await writeAudit({ userId: user.id, username: user.username, action: "mfa_setup_started", status: "success", ip, userAgent: ua });
  res.json({
    ok: true,
    requiresMfa: false,
    stage: "mfa_setup",
    qrCodeDataUrl: qr,
    secretBase32: secret.base32,
    next: "/api/auth/mfa/enable",
  });
});

// ---------------- MFA ENABLE (first-time confirm) ----------------
authRouter.post("/mfa/enable", async (req: Request, res: Response) => {
  const userIdRaw = req.cookies?.[PENDING_COOKIE];
  const userId = Number(userIdRaw);
  const { code } = (req.body ?? {}) as { code?: string };
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  if (!Number.isInteger(userId) || userId <= 0) {
    res.status(400).json({ ok: false, error: "No pending login" });
    return;
  }
  if (!code || !/^[0-9]{6}$/.test(code)) {
    res.status(400).json({ ok: false, error: "6-digit code required" });
    return;
  }

  const { rows } = await query<{ secret: string; is_enabled: boolean }>(
    "SELECT secret, is_enabled FROM mfa_secrets WHERE user_id = $1",
    [userId]
  );
  const mfa = rows[0];
  if (!mfa) {
    res.status(400).json({ ok: false, error: "No MFA setup in progress" });
    return;
  }

  const verified = speakeasy.totp.verify({
    secret: mfa.secret,
    encoding: "base32",
    token: code,
    window: env.mfaWindow,
  });

  if (!verified) {
    await writeAudit({ userId, action: "mfa_failed", status: "failure", ip, userAgent: ua, details: { stage: "enable" } });
    res.status(401).json({ ok: false, error: "Invalid code" });
    return;
  }

  await query(
    "UPDATE mfa_secrets SET is_enabled = TRUE, confirmed_at = NOW() WHERE user_id = $1",
    [userId]
  );

  const { rows: uRows } = await query<{ id: number; username: string; role: Role }>(
    "SELECT id, username, role FROM users WHERE id = $1",
    [userId]
  );
  const u = uRows[0];
  if (!u) {
    res.status(400).json({ ok: false, error: "User not found" });
    return;
  }
  const token = signAccessToken({ sub: u.id, username: u.username, role: u.role });
  setTokenCookie(res, token);
  res.clearCookie(PENDING_COOKIE, { path: "/" });
  await writeAudit({ userId: u.id, username: u.username, action: "mfa_enabled", status: "success", ip, userAgent: ua });
  await writeAudit({ userId: u.id, username: u.username, action: "login_success", status: "success", ip, userAgent: ua });
  res.json({ ok: true, user: { id: u.id, username: u.username, role: u.role } });
});

// ---------------- MFA VERIFY (subsequent logins) ----------------
authRouter.post("/mfa/verify", async (req: Request, res: Response) => {
  const userIdRaw = req.cookies?.[PENDING_COOKIE];
  const userId = Number(userIdRaw);
  const { code } = (req.body ?? {}) as { code?: string };
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  if (!Number.isInteger(userId) || userId <= 0) {
    res.status(400).json({ ok: false, error: "No pending login" });
    return;
  }
  if (!code || !/^[0-9]{6}$/.test(code)) {
    res.status(400).json({ ok: false, error: "6-digit code required" });
    return;
  }

  const { rows } = await query<{ secret: string; is_enabled: boolean }>(
    "SELECT secret, is_enabled FROM mfa_secrets WHERE user_id = $1",
    [userId]
  );
  const mfa = rows[0];
  if (!mfa || !mfa.is_enabled) {
    res.status(400).json({ ok: false, error: "MFA not enabled for this user" });
    return;
  }

  const verified = speakeasy.totp.verify({
    secret: mfa.secret,
    encoding: "base32",
    token: code,
    window: env.mfaWindow,
  });

  if (!verified) {
    await writeAudit({ userId, action: "mfa_failed", status: "failure", ip, userAgent: ua, details: { stage: "verify" } });
    await raiseAlert({
      alertType: "mfa_failures",
      severity: "medium",
      title: "Failed MFA verification",
      relatedUser: String(userId),
      ip,
    });
    res.status(401).json({ ok: false, error: "Invalid code" });
    return;
  }

  const { rows: uRows } = await query<{ id: number; username: string; role: Role }>(
    "SELECT id, username, role FROM users WHERE id = $1",
    [userId]
  );
  const u = uRows[0];
  if (!u) {
    res.status(400).json({ ok: false, error: "User not found" });
    return;
  }
  const token = signAccessToken({ sub: u.id, username: u.username, role: u.role });
  setTokenCookie(res, token);
  res.clearCookie(PENDING_COOKIE, { path: "/" });
  await writeAudit({ userId: u.id, username: u.username, action: "mfa_verified", status: "success", ip, userAgent: ua });
  await writeAudit({ userId: u.id, username: u.username, action: "login_success", status: "success", ip, userAgent: ua });
  res.json({ ok: true, user: { id: u.id, username: u.username, role: u.role } });
});

// ---------------- LOGOUT ----------------
authRouter.post("/logout", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  clearAuthCookies(res);
  await writeAudit({
    userId: user.id,
    username: user.username,
    action: "logout",
    status: "success",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });
  res.json({ ok: true });
});

// ---------------- ME ----------------
authRouter.get("/me", authenticate, (req: Request, res: Response) => {
  res.json({ ok: true, user: req.user });
});

logger.info("[auth] routes registered");

// ---------------- SIGN UP (public) ----------------
authRouter.post("/signup", loginLimiter, async (req: Request, res: Response) => {
  const { username, email, full_name, password, role } = (req.body ?? {}) as {
    username?: string; email?: string; full_name?: string; password?: string; role?: Role;
  };
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  if (!username || !email || !full_name || !password) {
    res.status(400).json({ ok: false, error: "username, email, full_name, password required" });
    return;
  }
  if (username.length < 3 || username.length > 50) {
    res.status(400).json({ ok: false, error: "Username must be 3-50 characters" });
    return;
  }
  if (password.length < 8) {
    res.status(400).json({ ok: false, error: "Password must be at least 8 characters" });
    return;
  }
  const requestedRole: Role = role === "researcher" || role === "viewer" ? role : "viewer";

  const existing = await query<{ id: number }>(
    "SELECT id FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)",
    [username, email]
  );
  if (existing.rows.length > 0) {
    res.status(409).json({ ok: false, error: "Username or email already exists" });
    return;
  }

  const hash = await bcrypt.hash(password, 12);
  const result = await query<{ id: number }>(
    `INSERT INTO users (username, email, full_name, password_hash, role, is_active, is_approved)
     VALUES ($1, $2, $3, $4, $5, TRUE, FALSE) RETURNING id`,
    [username, email, full_name, hash, requestedRole]
  );
  const newId = result.rows[0]?.id;

  await writeAudit({
    userId: newId ?? null,
    username,
    action: "signup_pending",
    status: "success",
    ip,
    userAgent: ua,
    details: { email, requestedRole },
  });

  res.status(201).json({ ok: true, message: "Account created. Awaiting administrator approval." });
});
