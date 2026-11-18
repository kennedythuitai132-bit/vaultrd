import "dotenv/config";
import bcrypt from "bcrypt";
import pg from "pg";

const { Client } = pg;

const DEMO_USERS = [
  { username: "admin",       email: "admin@vaultrd.local",       fullName: "System Administrator", role: "admin",      password: "Admin@123" },
  { username: "researcher1", email: "researcher1@vaultrd.local", fullName: "Researcher One",       role: "researcher", password: "Researcher@123" },
  { username: "viewer1",     email: "viewer1@vaultrd.local",     fullName: "Viewer One",           role: "viewer",     password: "Viewer@123" },
] as const;

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
  await client.connect();
  console.log("Connected.");

  for (const u of DEMO_USERS) {
    const hash = await bcrypt.hash(u.password, 12);
    const r = await client.query(
      `INSERT INTO users (username, email, full_name, password_hash, role, is_active)
       VALUES ($1, $2, $3, $4, $5, TRUE)
       ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
       RETURNING id`,
      [u.username, u.email, u.fullName, hash, u.role]
    );
    console.log("  seeded " + u.role + ": " + u.username + " (id=" + r.rows[0].id + ")");
  }

  const { rows } = await client.query("SELECT username, role, is_active FROM users ORDER BY id");
  console.log("Users in DB:");
  for (const r of rows) console.log("   - " + r.username + " -> " + r.role + " (active=" + r.is_active + ")");

  await client.end();
  console.log("Done.");
}

main().catch((e) => { console.error("Seed failed:", e); process.exitCode = 1; });
