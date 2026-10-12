import { PrismaClient } from "@prisma/client";

/**
 * Cấu hình timeout mặc định cho interactive transactions (Serializable / Heavy Load)
 * Tránh lỗi timeout 5s mặc định khi hệ thống chịu tải cao hoặc độ trễ mạng đám mây.
 */
export const DEFAULT_TRANSACTION_OPTIONS = {
  maxWait: 10000,
  timeout: 15000,
} as const;

export const prisma = new PrismaClient({
  log:
    process.env.NODE_ENV === "development"
      ? ["query", "error", "warn"]
      : ["error", "warn"],
});
