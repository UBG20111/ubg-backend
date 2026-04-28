CREATE TABLE IF NOT EXISTS app_users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bid_opportunities (
  id BIGSERIAL PRIMARY KEY,
  project_name TEXT NOT NULL,
  company TEXT NOT NULL,
  status TEXT DEFAULT 'Opportunities',
  due_date DATE,
  source TEXT,
  estimator TEXT,
  notes TEXT,
  created_by_user_id BIGINT REFERENCES app_users(id),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bid_intents (
  id BIGSERIAL PRIMARY KEY,
  bid_id BIGINT REFERENCES bid_opportunities(id) ON DELETE CASCADE,
  user_id BIGINT REFERENCES app_users(id),
  intent TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE app_users
ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';

ALTER TABLE app_users
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;

ALTER TABLE app_users
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

ALTER TABLE bid_opportunities
ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Opportunities';

ALTER TABLE bid_opportunities
ADD COLUMN IF NOT EXISTS due_date DATE;

ALTER TABLE bid_opportunities
ADD COLUMN IF NOT EXISTS source TEXT;

ALTER TABLE bid_opportunities
ADD COLUMN IF NOT EXISTS estimator TEXT;

ALTER TABLE bid_opportunities
ADD COLUMN IF NOT EXISTS notes TEXT;

ALTER TABLE bid_opportunities
ADD COLUMN IF NOT EXISTS created_by_user_id BIGINT REFERENCES app_users(id);

ALTER TABLE bid_opportunities
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

ALTER TABLE bid_intents
ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES app_users(id);

CREATE INDEX IF NOT EXISTS idx_app_users_email
ON app_users(email);

CREATE INDEX IF NOT EXISTS idx_bid_opportunities_status
ON bid_opportunities(status);

CREATE INDEX IF NOT EXISTS idx_bid_opportunities_due_date
ON bid_opportunities(due_date);

CREATE INDEX IF NOT EXISTS idx_bid_opportunities_created_at
ON bid_opportunities(created_at);

CREATE INDEX IF NOT EXISTS idx_bid_intents_bid_id
ON bid_intents(bid_id);
