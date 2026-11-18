import express, { type Request, type Response, type NextFunction } from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { env } from "./config/env.js";
import { pool } from "./config/db.js";
import { logger } from "./utils/logger.js";
import { authRouter } from "./routes/auth.js";
import { filesRouter } from "./routes/files.js";
import { usersRouter } from "./routes/users.js";
import { auditRouter } from "./routes/audit.js";
import { alertsRouter } from "./routes/alerts.js";
import { reportsRouter } from "./routes/reports.js";
import { grantsRouter } from "./routes/grants.js";
import { departmentsRouter } from "./routes/departments.js";
import { notificationsRouter } from "./routes/notifications.js";
import { settingsRouter } from "./routes/settings.js";
import { versionsRouter } from "./routes/versions.js";
import { commentsRouter } from "./routes/comments.js";
import { shareRouter } from "./routes/share.js";
import { catalogueRouter } from "./routes/catalogue.js";
import { loginHistoryRouter } from "./routes/loginHistory.js";
import { passwordResetRouter } from "./routes/passwordReset.js";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: env.frontendUrl, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get("/api/health", (_req: Request, res: Response) => {
  res.json({ ok: true, service: "VaultRD", env: env.nodeEnv, time: new Date().toISOString() });
});

app.use("/api/auth", authRouter);
app.use("/api/files", filesRouter);
app.use("/api/users", usersRouter);
app.use("/api/audit", auditRouter);
app.use("/api/alerts", alertsRouter);
app.use("/api/reports", reportsRouter);
app.use("/api/grants", grantsRouter);
app.use("/api/departments", departmentsRouter);
app.use("/api/notifications", notificationsRouter);
app.use("/api/settings", settingsRouter);
app.use("/api/versions", versionsRouter);
app.use("/api/comments", commentsRouter);
app.use("/api/share", shareRouter);
app.use("/api/catalogue", catalogueRouter);
app.use("/api/login-history", loginHistoryRouter);
app.use("/api/password-reset", passwordResetRouter);


const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.join(__dirname, "..", "..", "frontend");
app.use("/assets", express.static(path.join(frontendDir, "assets")));
app.use("/pages", express.static(path.join(frontendDir, "pages")));
app.get("/", (_req: Request, res: Response) => {
  res.redirect("/pages/login.html");
});
app.use((_req, res) => res.status(404).json({ ok: false, error: "Not found" }));

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  logger.error("[error]", err);
  res.status(500).json({ ok: false, error: "Internal server error" });
});

const server = app.listen(env.port, () => {
  logger.info("VaultRD backend running at http://localhost:" + env.port);
  logger.info("Health: http://localhost:" + env.port + "/api/health");
});

const shutdown = async (signal: string) => {
  logger.info("Shutting down (" + signal + ")");
  server.close(() => {});
  try { await pool.end(); } catch {}
  process.exit(0);
};
process.on("SIGINT", () => { void shutdown("SIGINT"); });
process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
