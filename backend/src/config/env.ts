import "dotenv/config";

function required(key: string): string {
  const v = process.env[key];
  if (!v || v.trim() === "") {
    console.error("FATAL: missing required env var: " + key);
    process.exit(1);
  }
  return v;
}

function optional(key: string, fallback: string): string {
  const v = process.env[key];
  return v && v.trim() !== "" ? v : fallback;
}

export const env = {
  nodeEnv: optional("NODE_ENV", "development"),
  port: Number(optional("PORT", "8080")),
  frontendUrl: optional("FRONTEND_URL", "http://localhost:8080"),
  databaseUrl: required("DATABASE_URL"),
  supabaseUrl: required("SUPABASE_URL"),
  supabaseServiceRoleKey: required("SUPABASE_SERVICE_ROLE_KEY"),
  supabaseBucket: optional("SUPABASE_STORAGE_BUCKET", "research-files"),
  jwtSecret: required("JWT_SECRET"),
  jwtExpiresIn: optional("JWT_EXPIRES_IN", "2h"),
  encryptionKey: required("ENCRYPTION_KEY"),
  mfaIssuer: optional("MFA_ISSUER", "VaultRD"),
  mfaWindow: Number(optional("MFA_WINDOW", "1")),
  loginMaxAttempts: Number(optional("LOGIN_MAX_ATTEMPTS", "5")),
  loginWindowMinutes: Number(optional("LOGIN_WINDOW_MINUTES", "15")),
};

if (env.encryptionKey.length !== 64) {
  console.error("FATAL: ENCRYPTION_KEY must be 64 hex chars (32 bytes)");
  process.exit(1);
}
if (env.jwtSecret.length < 32) {
  console.error("FATAL: JWT_SECRET must be at least 32 chars");
  process.exit(1);
}
