-- VaultRD schema
DROP TABLE IF EXISTS security_alerts CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS login_attempts CASCADE;
DROP TABLE IF EXISTS mfa_secrets CASCADE;
DROP TABLE IF EXISTS research_files CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TYPE IF EXISTS user_role CASCADE;
DROP TYPE IF EXISTS audit_status CASCADE;
DROP TYPE IF EXISTS alert_severity CASCADE;
DROP TYPE IF EXISTS alert_status CASCADE;
CREATE TYPE user_role AS ENUM ('admin','researcher','viewer');
CREATE TYPE audit_status AS ENUM ('success','failure');
CREATE TYPE alert_severity AS ENUM ('low','medium','high');
CREATE TYPE alert_status AS ENUM ('open','resolved');
CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  full_name VARCHAR(150) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role user_role NOT NULL DEFAULT 'researcher',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_username ON users (LOWER(username));
CREATE INDEX idx_users_email ON users (LOWER(email));
CREATE INDEX idx_users_role ON users (role);
CREATE TABLE mfa_secrets (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  secret VARCHAR(255) NOT NULL,
  is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  confirmed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_user ON mfa_secrets (user_id);
CREATE TABLE research_files (
  id BIGSERIAL PRIMARY KEY,
  owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  title VARCHAR(200) NOT NULL,
  project_code VARCHAR(50) NOT NULL,
  description TEXT,
  original_name VARCHAR(255) NOT NULL,
  mime_type VARCHAR(100) NOT NULL,
  size_bytes BIGINT NOT NULL,
  storage_path VARCHAR(500) NOT NULL,
  checksum_sha256 VARCHAR(64) NOT NULL,
  iv VARCHAR(64) NOT NULL,
  auth_tag VARCHAR(64) NOT NULL,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_files_owner ON research_files (owner_id);
CREATE INDEX idx_files_project_code ON research_files (project_code);
CREATE INDEX idx_files_created_at ON research_files (created_at DESC);
CREATE INDEX idx_files_not_deleted ON research_files (is_deleted) WHERE is_deleted = FALSE;
CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  username VARCHAR(50),
  action VARCHAR(80) NOT NULL,
  resource_type VARCHAR(40),
  resource_id BIGINT,
  status audit_status NOT NULL,
  ip_address VARCHAR(45),
  user_agent VARCHAR(500),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_user ON audit_logs (user_id);
CREATE INDEX idx_audit_action ON audit_logs (action);
CREATE INDEX idx_audit_status ON audit_logs (status);
CREATE INDEX idx_audit_created_at ON audit_logs (created_at DESC);
CREATE TABLE login_attempts (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  ip_address VARCHAR(45),
  success BOOLEAN NOT NULL,
  reason VARCHAR(120),
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_login_attempts_user_time ON login_attempts (LOWER(username), attempted_at DESC);
CREATE INDEX idx_login_attempts_ip_time ON login_attempts (ip_address, attempted_at DESC);
CREATE TABLE security_alerts (
  id BIGSERIAL PRIMARY KEY,
  alert_type VARCHAR(50) NOT NULL,
  severity alert_severity NOT NULL,
  status alert_status NOT NULL DEFAULT 'open',
  title VARCHAR(200) NOT NULL,
  description TEXT,
  related_user VARCHAR(50),
  ip_address VARCHAR(45),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  resolved_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  resolved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_alerts_status ON security_alerts (status);
CREATE INDEX idx_alerts_severity ON security_alerts (severity);
CREATE INDEX idx_alerts_created ON security_alerts (created_at DESC);
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_files_updated_at BEFORE UPDATE ON research_files FOR EACH ROW EXECUTE FUNCTION set_updated_at();
