export type Role = "admin" | "researcher" | "viewer";

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  is_approved: boolean;
}

export interface JwtPayload {
  sub: number;
  username: string;
  role: Role;
}

export type AuditAction =
  | "login_success"
  | "login_failed"
  | "login_rate_limited"
  | "logout"
  | "mfa_setup_started"
  | "mfa_enabled"
  | "mfa_verified"
  | "mfa_failed"
  | "role_denied"
  | "file_uploaded"
  | "file_downloaded"
  | "file_listed"
  | "file_deleted"
  | "user_created"
  | "user_updated"
  | "audit_viewed"
  | "alerts_viewed"
  | "alert_resolved"
  | "reports_viewed" | "signup_pending" | "signup_approved" | "signup_rejected" | "signup_rejected_login";

export type AuditStatus = "success" | "failure";

export interface ResearchFile {
  id: number;
  owner_id: number;
  title: string;
  project_code: string;
  description: string | null;
  original_name: string;
  mime_type: string;
  size_bytes: number;
  storage_path: string;
  checksum_sha256: string;
  is_deleted: boolean;
  created_at: string;
  updated_at: string;
  owner_username?: string;
}
