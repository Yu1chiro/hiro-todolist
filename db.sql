CREATE TABLE IF NOT EXISTS tasks (
  id           SERIAL PRIMARY KEY,
  name         VARCHAR(150) NOT NULL,
  due_at       DATE         NOT NULL,
  category     VARCHAR(20)  NOT NULL CHECK (category IN ('Work','Study','Productive','Hobby')),
  type         VARCHAR(10)  NOT NULL CHECK (type IN ('Low','Medium','Urgent')),
  description  TEXT         NOT NULL DEFAULT '',
  is_done      BOOLEAN      NOT NULL DEFAULT FALSE,
  completed_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tasks_due_at ON tasks (due_at);
CREATE INDEX IF NOT EXISTS idx_tasks_is_done ON tasks (is_done);