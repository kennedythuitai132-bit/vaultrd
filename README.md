# VaultRD: Secure Research Data Management System

VaultRD is a full-stack platform for storing, sharing and auditing sensitive research data. Files are encrypted before they leave the server, every action is logged, and access is controlled by role and by multi-factor authentication.

## Features

**Security**
- Password login with bcrypt hashing (cost 12)
- TOTP multi-factor authentication (authenticator app + QR setup)
- JWT sessions in HttpOnly cookies, CSRF double-submit protection
- Rate limiting on login and signup, with brute-force alerts
- AES-256-GCM encryption of every uploaded file (authenticated encryption)
- Role-based access control (admin / researcher / viewer) enforced server-side

**Research workflow**
- Encrypted upload, authorised download, delete
- File comments, version records, expiring share links
- Searchable research catalogue
- Grants, departments, collaborators
- Notifications and per-user settings

**Administration**
- Signup with admin approval (pending users cannot log in)
- User management: create, approve, activate/deactivate
- Audit log with filters and CSV export
- Security alerts with resolve workflow
- System reports with CSV export

**UI**
- Split-panel login/signup, sidebar dashboard shell
- Light and dark mode, responsive layout, Lucide icons, Chart.js

## Tech stack

| Layer | Technology |
|-------|------------|
| Backend | Node.js, TypeScript, Express (run with `tsx`) |
| Database | Supabase PostgreSQL (via `pg`) |
| File storage | Supabase Storage (encrypted blobs) |
| Auth | JWT cookies, bcrypt, TOTP (speakeasy + qrcode) |
| Security middleware | helmet, cors, express-rate-limit, CSRF |
| Frontend | HTML, CSS, vanilla JavaScript (served by Express) |

## Project structure

## Getting started

### Prerequisites
- Node.js 18 or newer
- A Supabase project (database + a Storage bucket named `research-files`)

### 1. Install

```bash
git clone https://github.com/kennedythuitai132-bit/vaultrd.git
cd vaultrd/backend
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

| Variable | Description |
|----------|-------------|
| PORT | Server port (default 8080) |
| NODE_ENV | development or production |
| FRONTEND_URL | Allowed CORS origin |
| DATABASE_URL | Supabase Postgres connection string (session pooler) |
| SUPABASE_URL | Supabase project URL |
| SUPABASE_SERVICE_ROLE_KEY | Supabase service role key (server only) |
| SUPABASE_STORAGE_BUCKET | Storage bucket name |
| JWT_SECRET | Long random string (64+ chars) |
| JWT_EXPIRES_IN | Session lifetime, e.g. 2h |
| ENCRYPTION_KEY | 64 hex characters (32 bytes) for AES-256-GCM |
| MFA_ISSUER | Name shown in authenticator apps |
| MFA_WINDOW | TOTP tolerance window |
| LOGIN_MAX_ATTEMPTS / LOGIN_WINDOW_MINUTES | Rate-limit settings |

Generate secrets:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. Set up the database

```bash
npm run db:migrate
npx tsx src/database/seed.ts
```

### 4. Run

```bash
npm run dev
```

Open http://localhost:8080/pages/login.html
Health check: http://localhost:8080/api/health

On first login every user is guided through MFA setup (scan the QR code with an authenticator app).

## API overview

All routes are under /api and require authentication unless noted.

| Area | Routes |
|------|--------|
| Auth | POST /auth/login, /auth/signup (public), /auth/mfa/*, /auth/logout, GET /auth/me |
| Users (admin) | GET/POST /users, PATCH /users/:id, PATCH /users/:id/approve |
| Files | GET/POST /files, GET /files/:id/download, DELETE /files/:id |
| Audit (admin) | GET /audit |
| Alerts (admin) | GET /alerts, PATCH /alerts/:id/resolve |
| Reports (admin) | GET /reports/summary |
| Grants | GET/POST /grants, DELETE /grants/:id |
| Departments | GET /departments, admin: POST/PATCH/DELETE |
| Comments | GET/POST /comments/:fileId |
| Share links | POST/GET/DELETE /share, public GET /share/:token |
| Catalogue | GET /catalogue, POST /catalogue/publish/:fileId |
| Notifications | GET /notifications, PATCH /notifications/:id/read |
| Settings | GET/PATCH /settings, PATCH /settings/profile, /settings/password |
| Misc | /versions, /login-history, /password-reset |

## Roles

| Role | Can do |
|------|--------|
| Admin | Everything, including users, audit, alerts, reports |
| Researcher | Upload, manage own files, comment, grants, catalogue |
| Viewer | Read-only access to permitted content |

## Security notes

- Never commit .env. It is git-ignored; .env.example holds placeholders only.
- Rotate JWT_SECRET, ENCRYPTION_KEY, the database password and the Supabase service key before any deployment.
- Changing ENCRYPTION_KEY makes previously encrypted files unreadable. Back it up securely.
- Enable the Content Security Policy in server.ts before production.
- Serve over HTTPS in production and use secure cookies.

## Deployment

Deploy the backend folder as a Node web service (for example on Render): build `npm install && npm run build`, start `npm start`, and add the environment variables above. Express serves the frontend folder, so one service runs the whole app.

## Roadmap

Drag-and-drop upload, file preview, version history UI, email verification and password-reset emails, analytics with PDF/Excel export, AI research assistant.

## Author

Boniface Matage Birai, Digital Computer Forensics, Zetech University.

## License

MIT
