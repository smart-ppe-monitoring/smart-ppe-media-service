-- Migration: 20261014160000_add_file_records_full_text_search_gin_index
-- Description: Thêm chỉ mục GIN (Generalized Inverted Index) phục vụ tối ưu hóa PostgreSQL Full-Text Search cho bảng file_records (original_name, file_name, folder) - SEC-26

-- 1. Create GIN index for Full-Text Search on file_records table
CREATE INDEX IF NOT EXISTS "idx_file_records_fts" ON "file_records" USING gin (
    to_tsvector('simple', coalesce("original_name", '') || ' ' || coalesce("file_name", '') || ' ' || coalesce("folder", ''))
);
