import "dotenv/config";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Client } from "pg";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(__dirname, "..", "..", "database", "schema.sql");

async function main() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) { console.error("DATABASE_URL missing"); process.exit(1); }
  console.log("Connecting...");
  const client = new Client({ connectionString, ssl: { rejectUnauthorized: false } });
  try {
    await client.connect();
    console.log("Connected.");
    const sql = readFileSync(schemaPath, "utf8");
    console.log("Running " + schemaPath + "...");
    await client.query(sql);
    console.log("Schema applied successfully.");
    const r = await client.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = $2 ORDER BY table_name",
      ["public", "BASE TABLE"]
    );
    console.log("Tables:");
    for (const row of r.rows) console.log("   - " + row.table_name);
  } catch (e) {
    console.error("Migration failed:", e);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}

main();
