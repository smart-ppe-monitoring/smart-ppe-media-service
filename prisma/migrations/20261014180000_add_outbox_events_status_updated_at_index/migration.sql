-- Migration: 20261014180000_add_outbox_events_status_updated_at_index
-- Description: Composite index on outbox_events(status, updated_at) to accelerate pending / stalled event polling - SEC-57

CREATE INDEX IF NOT EXISTS "outbox_events_status_updated_at_idx" ON "outbox_events"("status", "updated_at");
