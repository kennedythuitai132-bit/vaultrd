import { writeFileSync, existsSync, unlinkSync } from "node:fs";

const BASE = "http://localhost:8080";

function saveCookies(res, filename) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  if (!raw.length) return false;
  const lines = ["# Netscape HTTP Cookie File"];
  for (const c of raw) {
    const parts = c.split(";").map(s => s.trim());
    const pair = parts[0];
    const attrs = parts.slice(1);
    const eq = pair.indexOf("=");
    const name = pair.slice(0, eq);
    const val = pair.slice(eq + 1);
    let path = "/";
    for (const a of attrs) {
      if (a.toLowerCase().startsWith("path=")) path = a.slice(5);
    }
    lines.push("127.0.0.1\tFALSE\t" + path + "\tFALSE\t0\t" + name + "\t" + val);
  }
  writeFileSync(filename, lines.join("\n"), "utf8");
  return true;
}

async function main() {
  for (const f of ["cookies.txt", "qrCodeDataUrl.txt"]) {
    if (existsSync(f)) { try { unlinkSync(f); } catch (e) {} }
  }

  console.log("");
  console.log("=== STAGE 1: admin login ===");
  console.log("");
  const res = await fetch(BASE + "/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "Admin@123" }),
  });
  const body = await res.json();
  console.log("status:", res.status);
  console.log("ok:", body.ok);
  console.log("stage:", body.stage);
  console.log("requiresMfa:", body.requiresMfa);

  if (!body.ok) {
    console.error("");
    console.error("LOGIN FAILED:", body);
    process.exit(1);
  }

  saveCookies(res, "cookies.txt");

  if (body.stage === "mfa_setup") {
    console.log("");
    console.log("=== SECRET (add to Authenticator) ===");
    console.log("secretBase32:", body.secretBase32);
    writeFileSync("qrCodeDataUrl.txt", body.qrCodeDataUrl, "utf8");
    console.log("");
    console.log("QR saved to qrCodeDataUrl.txt");
    console.log("");
    console.log("ACTION:");
    console.log("1. Open Authenticator app");
    console.log("2. Add account -> Enter setup key (or scan QR)");
    console.log("3. Name: VaultRD   Key: " + body.secretBase32);
    console.log("4. Note the 6-digit code it shows");
    console.log("");
    console.log("Then run BLOCK 2 with that code.");
  } else if (body.stage === "mfa_verify") {
    console.log("");
    console.log("MFA already enabled. Use BLOCK 2b instead.");
    console.log("Get 6-digit code from Authenticator and run BLOCK 2b.");
  }
}

main().catch(function(e) { console.error(e); process.exit(1); });
