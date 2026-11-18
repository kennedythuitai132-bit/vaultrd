type Level = "info" | "warn" | "error";

function log(level: Level, msg: string, meta?: unknown) {
  const ts = new Date().toISOString();
  const prefix = ts + " [" + level.toUpperCase() + "]";
  if (meta !== undefined) {
    console.log(prefix, msg, meta);
  } else {
    console.log(prefix, msg);
  }
}

export const logger = {
  info: (msg: string, meta?: unknown) => log("info", msg, meta),
  warn: (msg: string, meta?: unknown) => log("warn", msg, meta),
  error: (msg: string, meta?: unknown) => log("error", msg, meta),
};
