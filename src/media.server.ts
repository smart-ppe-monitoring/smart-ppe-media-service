import "dotenv/config";
import dns from "node:dns";

// Force IPv4-first resolution in Node.js runtime to prevent ENETUNREACH on platforms without IPv6 routing
try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  // Graceful fallback if not supported in runtime
}

import mediaApp from "./media.app";
import { envConfig } from "./config/env.config";
import { storageCleanupSubscriber } from "./common/subscribers/storage-cleanup.subscriber";
import { eventBus } from "./common/services/event-bus.service";
import { prisma } from "./database/prisma.client";

const PORT = envConfig.media.port;

/**
 * Media & File Storage Microservice Process (Phase 6: Second Satellite Service)
 *
 * Chịu trách nhiệm độc quyền:
 * 1. Phục vụ HTTP API cho File & Media domain (upload, download, view, delete)
 * 2. Xử lý tối ưu hóa, crop, nén và chuyển đổi định dạng ảnh bằng Sharp
 * 3. Lắng nghe các event topics liên quan tới file từ Redis EventBus qua StorageCleanupSubscriber
 * 4. Quét dọn tệp tin rác mồ côi (orphan files cleanup)
 */
export const server = mediaApp.listen(PORT, async () => {
  console.log(
    `[Media Service] Running on http://localhost:${PORT} in ${envConfig.nodeEnv} mode`,
  );

  // 1. Đăng ký subscriber lắng nghe events liên quan tới storage
  storageCleanupSubscriber.register();

  console.log(
    "[Media Service] ✅ StorageCleanupSubscriber is active and listening for storage events.",
  );
});

let isShuttingDown = false;

export async function handleMediaShutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(
    `\n[Media Service] Received ${signal}. Starting graceful shutdown...`,
  );

  const forceExitTimer = setTimeout(() => {
    console.error(
      "[Media Service] Graceful shutdown timed out (10s). Forcing termination.",
    );
    process.exit(1);
  }, 10000);
  forceExitTimer.unref();

  try {
    // 1. Close idle HTTP connections
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }

    // 2. Stop accepting new HTTP requests
    await new Promise<void>((resolve) => {
      server.close((err) => {
        if (err) {
          console.warn(
            "[Media Service] Warning while closing HTTP server:",
            err.message,
          );
        } else {
          console.log("[Media Service] HTTP server closed.");
        }
        resolve();
      });
    });

    // 3. Close EventBus connection
    await eventBus.close();
    console.log("[Media Service] EventBus connection closed.");

    // 4. Disconnect Prisma DB client
    await prisma.$disconnect();
    console.log("[Media Service] Database client disconnected.");

    console.log("[Media Service] Graceful shutdown completed cleanly.");
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(0);
    }
  } catch (err: any) {
    console.error(
      "[Media Service] Error during graceful shutdown:",
      err.message,
    );
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(1);
    }
  }
}

process.on("SIGTERM", () => handleMediaShutdown("SIGTERM"));
process.on("SIGINT", () => handleMediaShutdown("SIGINT"));
