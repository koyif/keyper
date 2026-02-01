-- Remove search optimization indices

DROP INDEX IF EXISTS idx_secrets_user_type;
DROP INDEX IF EXISTS idx_secrets_metadata_gin;
DROP INDEX IF EXISTS idx_secrets_user_name;
