/**
 * Helper hỗ trợ Full-Text Search (FTS) cho PostgreSQL
 * Cung cấp các tiện ích xử lý, làm sạch chuỗi tìm kiếm và sinh tsquery an toàn chống lỗi cú pháp & SQL injection.
 */

/**
 * Xóa bỏ các ký tự điều khiển, toán tử đặc biệt của PostgreSQL tsquery và các payload nguy hiểm.
 * Chỉ giữ lại chữ cái Unicode (hỗ trợ tiếng Việt đầy đủ), chữ số, dấu gạch dưới, gạch ngang và dấu chấm.
 */
export function sanitizeFtsInput(input: string): string {
  if (!input) return "";
  return input
    .replace(/[^\p{L}\p{N}_\s.@-]/gu, " ")
    .replace(/--+/g, " ") // Loại bỏ chuỗi comment SQL
    .replace(/;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export type TsQueryMode = "prefix" | "exact" | "phrase" | "or";

/**
 * Xây dựng chuỗi tsquery chuẩn cho PostgreSQL:
 * - "prefix" (mặc định): 'word1':* & 'word2':* (phù hợp tìm kiếm gõ phím / autocomplete)
 * - "exact": 'word1' & 'word2' (khớp chính xác từng từ)
 * - "phrase": 'word1' <-> 'word2' (tìm kiếm cụm từ liền kề chính xác)
 * - "or": 'word1':* | 'word2':* (khớp một trong các từ)
 */
export function buildTsQuery(
  input: string,
  mode: TsQueryMode = "prefix",
): string | null {
  const sanitized = sanitizeFtsInput(input);
  if (!sanitized) return null;

  // Tách các từ theo khoảng trắng và dọn dẹp các ký tự nối ở đầu/cuối từ
  const words = sanitized
    .split(" ")
    .map((w) => w.replace(/'/g, "").replace(/^[-.@]+|[-.@]+$/g, "").trim())
    .filter((w) => w.length > 0);

  if (words.length === 0) return null;

  if (mode === "prefix") {
    // Tạo prefix query: 'word':*
    const tokens = words.map((w) => `'${w}':*`);
    return tokens.join(" & ");
  }

  if (mode === "exact") {
    const tokens = words.map((w) => `'${w}'`);
    return tokens.join(" & ");
  }

  if (mode === "phrase") {
    // Phrase search sử dụng toán tử khoảng cách liền kề <-> của PostgreSQL
    const tokens = words.map((w) => `'${w}'`);
    return tokens.join(" <-> ");
  }

  if (mode === "or") {
    const tokens = words.map((w) => `'${w}':*`);
    return tokens.join(" | ");
  }

  // Mặc định prefix
  return words.map((w) => `'${w}':*`).join(" & ");
}

/**
 * Chuẩn hóa từ khóa tìm kiếm:
 * Trả về null nếu chuỗi rỗng hoặc chỉ có khoảng trắng, ngược lại trả về chuỗi đã trim.
 */
export function normalizeSearchTerm(search?: string | null): string | null {
  if (!search) return null;
  const trimmed = search.trim();
  return trimmed.length > 0 ? trimmed : null;
}
