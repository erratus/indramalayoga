-- PostgreSQL schema for Indramala Yoga Sansthan
-- Run this once inside your Neon (or any Postgres) database before deploying.

CREATE TABLE IF NOT EXISTS users (
  uid      SERIAL PRIMARY KEY,
  name     VARCHAR(100) NOT NULL,
  lastname VARCHAR(100) NOT NULL,
  ph_no    VARCHAR(20)  UNIQUE NOT NULL,
  gender   VARCHAR(10),
  password TEXT         NOT NULL
);

CREATE TABLE IF NOT EXISTS instructors (
  tid       SERIAL PRIMARY KEY,
  name      VARCHAR(100) NOT NULL,
  lastname  VARCHAR(100) NOT NULL,
  ph_no     VARCHAR(20)  UNIQUE NOT NULL,
  dob       DATE,
  address   TEXT,
  reference TEXT,
  password  TEXT         NOT NULL
);

CREATE TABLE IF NOT EXISTS course (
  cid         SERIAL PRIMARY KEY,
  course_name VARCHAR(200) NOT NULL,
  price       NUMERIC(10,2),
  from_date   DATE,
  to_date     DATE
);

CREATE TABLE IF NOT EXISTS applicants (
  appid SERIAL PRIMARY KEY,
  uid   INTEGER REFERENCES users(uid)   ON DELETE CASCADE,
  cid   INTEGER REFERENCES course(cid)  ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS instructor_teaching (
  tid INTEGER REFERENCES instructors(tid) ON DELETE CASCADE,
  cid INTEGER REFERENCES course(cid)      ON DELETE CASCADE,
  PRIMARY KEY (tid, cid)
);

CREATE TABLE IF NOT EXISTS instructor_learning (
  tid         INTEGER REFERENCES instructors(tid) ON DELETE CASCADE,
  course_name VARCHAR(200),
  PRIMARY KEY (tid, course_name)
);

CREATE TABLE IF NOT EXISTS workshop_sign_in (
  id         SERIAL PRIMARY KEY,
  first_name VARCHAR(100) NOT NULL,
  last_name  VARCHAR(100) NOT NULL,
  ph_no      VARCHAR(20)  NOT NULL,
  comments   TEXT,
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

-- Session table required by connect-pg-simple.
-- Previously created automatically via createTableIfMissing; now managed here
-- to avoid an extra DDL round-trip on every Vercel cold start.
CREATE TABLE IF NOT EXISTS "session" (
  "sid"    varchar      NOT NULL COLLATE "default",
  "sess"   json         NOT NULL,
  "expire" timestamp(6) NOT NULL,
  CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE
) WITH (OIDS=FALSE);

CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
