-- 002_departments.sql  (safe to run more than once)
CREATE TABLE IF NOT EXISTS user_departments (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  department_id INT NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, department_id)
);

ALTER TABLE research_files ADD COLUMN IF NOT EXISTS department_id BIGINT REFERENCES departments(id) ON DELETE SET NULL;
ALTER TABLE grants         ADD COLUMN IF NOT EXISTS department_id BIGINT REFERENCES departments(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_files_department  ON research_files (department_id);
CREATE INDEX IF NOT EXISTS idx_grants_department ON grants (department_id);
CREATE INDEX IF NOT EXISTS idx_user_departments_dept ON user_departments (department_id);

-- department heads are always members of their department
INSERT INTO user_departments (user_id, department_id)
SELECT head_user_id, id FROM departments WHERE head_user_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- existing files and grants inherit their owner's department
UPDATE research_files f SET department_id = (
  SELECT ud.department_id FROM user_departments ud WHERE ud.user_id = f.owner_id ORDER BY ud.department_id LIMIT 1
) WHERE f.department_id IS NULL;

UPDATE grants g SET department_id = (
  SELECT ud.department_id FROM user_departments ud WHERE ud.user_id = g.owner_id ORDER BY ud.department_id LIMIT 1
) WHERE g.department_id IS NULL;