-- CRYPTARCH-17: unlimited quota = NULL (honest SQL, no magic sentinel).
-- The provisioning quota check skips when NULL; everything else displays it
-- as "unlimited".
ALTER TABLE users ALTER COLUMN db_quota DROP NOT NULL;
