import "dotenv/config";
import pg from "pg";

const { Client } = pg;

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
  try {
    await client.connect();
    const { rows } = await client.query("SELECT NOW() AS now, version() AS version");
    console.log("✅ DB reachable");
    console.log("   time:   ", rows[0].now);
    console.log("   version:", rows[0].version.split(",")[0]);
  } catch (err) {
    console.error("❌ DB ping failed:", err);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}

main();
