-- CRYPTARCH-146. With local accounts, whoever can set a user's password can
-- become that user; nothing inside Cryptarch prevents it. What it can do is
-- refuse to let an admin-set password do anything but be replaced, and keep
-- the trail honest about who could have been acting.
--
-- password_set_by: the admin who set the account's current password (create
-- or reset). NULL once the user sets their own — and for the bootstrap admin,
-- whose password the operator chose.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_set_by TEXT;

-- began_on_password_set_by: a session that SIGNED IN with an admin-set
-- password keeps that lineage for its life, across the rotation a password
-- change does — the admin who set it may be the one who changed it. Every
-- audit row the session writes says so.
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS began_on_password_set_by TEXT;
