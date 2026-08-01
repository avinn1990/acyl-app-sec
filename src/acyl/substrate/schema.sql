PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  target_path TEXT NOT NULL,
  git_url TEXT,
  pinned_revision TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  goals_json TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  role TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100,
  state TEXT NOT NULL DEFAULT 'open',
  payload_json TEXT NOT NULL DEFAULT '{}',
  release_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claims (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id),
  agent_id TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  claimed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'candidate',
  verdict TEXT,
  severity TEXT,
  title TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  vuln_class TEXT NOT NULL,
  path TEXT,
  symbol TEXT,
  source TEXT NOT NULL,
  rule_id TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(run_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  kind TEXT NOT NULL,
  path TEXT,
  symbol TEXT,
  line INTEGER,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS coverage (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  goal TEXT NOT NULL,
  area TEXT NOT NULL DEFAULT '',
  technique TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending',
  last_attempt_at TEXT,
  UNIQUE(run_id, goal, technique)
);

CREATE TABLE IF NOT EXISTS agent_sessions (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  role TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  token_count INTEGER NOT NULL DEFAULT 0,
  cost_estimate REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rule_gaps (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  finding_id TEXT NOT NULL REFERENCES findings(id),
  vuln_class TEXT NOT NULL,
  pattern_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
