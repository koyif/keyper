-- Add indices for efficient secret search operations
-- These indices support the database-level search functionality in SearchSecrets

-- Index for user + name lookups (most common search pattern)
-- Supports: WHERE user_id = X AND name ILIKE '%pattern%'
-- Partial index only on non-deleted secrets to improve query performance
CREATE INDEX idx_secrets_user_name
ON secrets(user_id, name)
WHERE is_deleted = false;

-- Index for user + updated_at (already exists but optimized for search)
-- Supports: ORDER BY updated_at DESC
-- Note: idx_secrets_user_id_is_deleted_updated_at already covers this

-- GIN index for JSONB metadata (category, tags, favorites)
-- Supports: WHERE metadata @> '{...}' (containment queries)
-- Supports: WHERE metadata->>'category' = 'work'
-- Supports: WHERE (metadata->>'is_favorite')::boolean = true
CREATE INDEX idx_secrets_metadata_gin
ON secrets USING GIN(metadata jsonb_path_ops);

-- Composite index for type filtering combined with user lookup
-- Supports: WHERE user_id = X AND type = Y
CREATE INDEX idx_secrets_user_type
ON secrets(user_id, type)
WHERE is_deleted = false;

-- Add comment explaining the search optimization
COMMENT ON INDEX idx_secrets_user_name IS 'Optimizes name-based search queries for non-deleted secrets';
COMMENT ON INDEX idx_secrets_metadata_gin IS 'Enables efficient JSONB queries for category, tags, and favorite filters';
COMMENT ON INDEX idx_secrets_user_type IS 'Optimizes type filtering in search queries';
