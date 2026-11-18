import crypto from "node:crypto";
import { env } from "../config/env.js";

const KEY = Buffer.from(env.encryptionKey, "hex");

export interface EncryptedPayload {
  ciphertext: Buffer;
  iv: string;
  authTag: string;
}

export function encryptBuffer(plaintext: Buffer): EncryptedPayload {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv: iv.toString("hex"), authTag: authTag.toString("hex") };
}

export function decryptBuffer(payload: EncryptedPayload): Buffer {
  const iv = Buffer.from(payload.iv, "hex");
  const authTag = Buffer.from(payload.authTag, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(payload.ciphertext), decipher.final()]);
}

export function sha256Hex(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("hex");
}
