import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { env } from "../config/env.js";

let cached: SupabaseClient | null = null;

export function getSupabase(): SupabaseClient {
  if (cached) return cached;
  cached = createClient(env.supabaseUrl, env.supabaseServiceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return cached;
}

export async function uploadToBucket(
  path: string,
  data: Buffer,
  contentType: string
): Promise<{ path: string }> {
  const sb = getSupabase();
  const { data: up, error } = await sb.storage
    .from(env.supabaseBucket)
    .upload(path, data, { contentType, upsert: false });
  if (error || !up) {
    throw new Error("Supabase upload failed: " + (error?.message ?? "unknown"));
  }
  return { path: up.path };
}

export async function downloadFromBucket(path: string): Promise<Buffer> {
  const sb = getSupabase();
  const { data, error } = await sb.storage.from(env.supabaseBucket).download(path);
  if (error || !data) {
    throw new Error("Supabase download failed: " + (error?.message ?? "unknown"));
  }
  const arrayBuffer = await data.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

export async function deleteFromBucket(path: string): Promise<void> {
  const sb = getSupabase();
  const { error } = await sb.storage.from(env.supabaseBucket).remove([path]);
  if (error) throw new Error("Supabase delete failed: " + error.message);
}
