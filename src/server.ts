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

const PORT = envConfig.media.port || envConfig.port || 8890;

let outboxRelayTimer: NodeJS.Timeout | null = null;
const OUTBOX_RELAY_INTERVAL_MS = 5000;

/**
 * SEC-12: Khởi chạy Outbox Relay Background Worker để quét định kỳ các bản ghi
 * outbox_events ở trạng thái PENDING và relay sang EventBus / Redis.
 */
export function startOutboxRelay(
  intervalMs: number = OUTBOX_RELAY_INTERVAL_MS,
  batchSize: number = 50,
): NodeJS.Timeout {
  if (outboxRelayTimer) {
    clearInterval(outboxRelayTimer);
  }
  outboxRelayTimer = setInterval(async () => {
    try {
      const relayed = await eventBus.relayPendingOutboxEvents(batchSize);
      if (relayed > 0) {
        console.log(`[Media Service] Relayed ${relayed} pending outbox events.`);
      }
    } catch (err: any) {
      console.warn(
        "[Media Service] Error in outbox relay worker:",
        err?.message || err,
      );
    }
  }, intervalMs);
  outboxRelayTimer.unref();
  return outboxRelayTimer;
}

export function stopOutboxRelay(): void {
  if (outboxRelayTimer) {
    clearInterval(outboxRelayTimer);
    outboxRelayTimer = null;
  }
}

/**
 * Media & File Storage Microservice Process (Phase 6: Second Satellite Service)
 *
 * Chịu trách nhiệm độc quyền:
 * 1. Phục vụ HTTP API cho File & Media domain (upload, download, view, delete)
 * 2. Xử lý tối ưu hóa, crop, nén và chuyển đổi định dạng ảnh bằng Sharp
 * 3. Lắng nghe các event topics liên quan tới file từ Redis EventBus qua StorageCleanupSubscriber
 * 4. Quét dọn tệp tin rác mồ côi (orphan files cleanup)
 * 5. Relay các sự kiện Transactional Outbox sang message bus (SEC-12)
 */
export const server =
  process.env.NODE_ENV === "test"
    ? null
    : mediaApp.listen(PORT, async () => {
        console.log(
          `[Media Service] Running on http://localhost:${PORT} in ${envConfig.nodeEnv} mode`,
        );

        // 1. Đăng ký subscriber lắng nghe events liên quan tới storage
        storageCleanupSubscriber.register();

        console.log(
          "[Media Service] ✅ StorageCleanupSubscriber is active and listening for storage events.",
        );

        // 2. SEC-12: Khởi chạy Outbox Relay Worker quét sự kiện PENDING định kỳ
        startOutboxRelay();
        console.log(
          "[Media Service] ✅ OutboxRelayWorker is running (polling every 5000ms).",
        );
      });

let isShuttingDown = false;

export function resetShutdownStateForTesting(): void {
  isShuttingDown = false;
}

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
    // 0. SEC-12: Dừng Outbox Relay Worker và xả sạch các sự kiện còn tồn đọng (graceful drain)
    stopOutboxRelay();
    try {
      const drained = await eventBus.relayPendingOutboxEvents(100);
      if (drained > 0) {
        console.log(
          `[Media Service] Drained ${drained} pending outbox events during shutdown.`,
        );
      }
    } catch (relayErr: any) {
      console.warn(
        "[Media Service] Warning while draining outbox events:",
        relayErr?.message || relayErr,
      );
    }

    // 1. Close idle HTTP connections
    if (server && typeof (server as any).closeIdleConnections === "function") {
      (server as any).closeIdleConnections();
    }

    // 2. Stop accepting new HTTP requests
    if (server) {
      await new Promise<void>((resolve) => {
        (server as any).close((err: any) => {
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
    }

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
