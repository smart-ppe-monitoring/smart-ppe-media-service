import { uuidv7 } from "uuidv7";

/**
 * Generate a UUID v7 (time-ordered UUID).
 * UUIDv7 encodes a Unix timestamp in the most-significant bits,
 * making it monotonically sortable and friendlier to B-tree indexes.
 */
export { uuidv7 };

/** Alias: generate a new UUID v7 */
export const generateId = uuidv7;

/**
 * Regex matching standard 36-character hyphenated UUID strings (8-4-4-4-12 hex groups, v1-v7).
 * SEC-15: Enforce strict RFC 4122 / RFC 9562 structure to prevent non-UUID inputs from causing 22P02 DB syntax errors.
 */
export const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Type guard verifying if an unknown value is a 36-character hyphenated UUID string.
 */
export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_REGEX.test(value);
}
