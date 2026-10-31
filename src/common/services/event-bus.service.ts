import { Queue, QueueOptions } from "bullmq";
import IORedis from "ioredis";
import { uuidv7 } from "uuidv7";
import { Prisma } from "@prisma/client-media";
import { envConfig } from "../../config/env.config";
import { encryptSecret, decryptSecret } from "../helpers/crypto.helper";
import {
  EVENT_NAMES,
  EVENT_BUS_CONSTANTS,
  EventName,
} from "../constants/event.constant";
import {
  EventEnvelope,
  EventHandler,
  EventPayloadMap,
} from "../types/event.type";
import {
  outboxRepository,
  OutboxRepository,
} from "../repositories/outbox.repository";
import {
  getTraceId,
  runWithTraceContext,
} from "../context/trace-context";

export interface PublishEventOptions {
  aggregateId?: string | null;
  traceId?: string;
  tx?: Prisma.TransactionClient;
  useOutbox?: boolean;
}

export interface DlqRecord {
  envelope: EventEnvelope;
  error: string;
  failedAt: number;
  attempts: number;
  status?: string;
  reprocessedAt?: number;
}

const isTestEnv =
  process.env.NODE_ENV === "test" ||
  process.argv.some((arg) => arg.includes("test")) ||
  process.env.npm_lifecycle_event === "test";

/**
 * Danh sách các trường dữ liệu nhạy cảm cần mã hóa AES-256-GCM trong Outbox (SEC-47).
 * Bao gồm cả token xác thực người dùng và các credential, presigned URL của Media/S3.
 */
export const SENSITIVE_OUTBOX_FIELDS = [
  "verifyToken",
  "resetToken",
  "deactivationToken",
  "password",
  "presignedUrl",
  "uploadUrl",
  "downloadUrl",
  "accessKey",
  "secretAccessKey",
  "sessionToken",
  "token",
  "apiKey",
] as const;

export class EventBusService {
  private queue?: Queue<EventEnvelope>;
  private notificationQueue?: Queue<EventEnvelope>;
  private dlqQueue?: Queue<DlqRecord>;
  private redisConnection?: IORedis;
  private isRedisAvailable = false;
  private handlers = new Map<string, Set<EventHandler>>();
  private readonly notificationEventNames = new Set<string>([
    EVENT_NAMES.AUTH_USER_REGISTERED,
    EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
    EVENT_NAMES.AUTH_PASSWORD_RESET_REQUESTED,
    EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
    EVENT_NAMES.AUTH_DEACTIVATION_REQUESTED,
  ]);
  private processedEventIds = new Map<string, number>(); // ID -> expiresAt
  private dlqEvents: DlqRecord[] = []; // In-memory DLQ store
  private inMemoryQueue: Array<{
    id: string;
    envelope: EventEnvelope;
    attempts: number;
  }> = [];
  private activeRetryTimers = new Set<NodeJS.Timeout>();
  private outboxRepo: OutboxRepository;
  private isProcessingInMemory = false;

  constructor(outboxRepo?: OutboxRepository, redisConnection?: IORedis) {
    this.outboxRepo = outboxRepo || outboxRepository;

    if (redisConnection) {
      this.redisConnection = redisConnection;
      this.isRedisAvailable = true;
    } else if (!isTestEnv && envConfig.redis.enabled) {
      this.initRedis();
    }
  }

  public setRedisConnectionForTesting(
    client: IORedis | any | undefined,
    isAvailable = true,
  ): void {
    this.redisConnection = client;
    this.isRedisAvailable = Boolean(client && isAvailable);
  }

  private initRedis(): void {
    try {
      this.redisConnection = new IORedis({
        host: envConfig.redis.host,
        port: envConfig.redis.port,
        password: envConfig.redis.password,
        maxRetriesPerRequest: null,
        enableReadyCheck: false,
        lazyConnect: true,
        retryStrategy: (times) => {
          if (times > 2) {
            this.isRedisAvailable = false;
            return null;
          }
          return Math.min(times * 200, 500);
        },
      });

      this.redisConnection.on("connect", () => {
        this.isRedisAvailable = true;
      });

      this.redisConnection.on("error", () => {
        this.isRedisAvailable = false;
      });

      this.redisConnection.connect().catch(() => {
        this.isRedisAvailable = false;
      });

      const queueOptions: QueueOptions = {
        connection: this.redisConnection,
        defaultJobOptions: {
          attempts: EVENT_BUS_CONSTANTS.DEFAULT_MAX_ATTEMPTS,
          backoff: {
            type: "exponential",
            delay: EVENT_BUS_CONSTANTS.DEFAULT_BACKOFF_DELAY_MS,
          },
          removeOnComplete: true,
          removeOnFail: false,
        },
      };

      this.queue = new Queue<EventEnvelope>(
        EVENT_BUS_CONSTANTS.DEFAULT_QUEUE_NAME,
        queueOptions,
      );

      this.notificationQueue = new Queue<EventEnvelope>(
        EVENT_BUS_CONSTANTS.NOTIFICATION_QUEUE_NAME,
        queueOptions,
      );

      this.dlqQueue = new Queue<DlqRecord>(
        EVENT_BUS_CONSTANTS.DLQ_QUEUE_NAME,
        queueOptions,
      );
    } catch {
      this.isRedisAvailable = false;
    }
  }

  /**
   * Đăng ký bên lắng nghe sự kiện (Consumer / Subscriber)
   */
  public subscribe<K extends EventName>(
    eventName: K,
    handler: EventHandler<EventPayloadMap[K]>,
  ): () => void {
    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, new Set());
    }
    this.handlers.get(eventName)!.add(handler as EventHandler);

    return () => {
      this.handlers.get(eventName)?.delete(handler as EventHandler);
    };
  }

  /**
   * Xuất bản sự kiện (Publisher).
   * Tự động áp dụng Transactional Outbox Pattern:
   * Nếu có `options.tx`, sự kiện được ghi vào bảng outbox_events trong transaction đó
   * và sẽ được Outbox Relay chuyển tiếp khi transaction commit.
   */
  public async publish<K extends EventName>(
    eventName: K,
    payload: EventPayloadMap[K],
    options?: PublishEventOptions,
  ): Promise<EventEnvelope<EventPayloadMap[K]>> {
    const traceId = options?.traceId || getTraceId() || uuidv7();

    const envelope: EventEnvelope<EventPayloadMap[K]> = {
      id: uuidv7(),
      name: eventName,
      payload,
      aggregateId: options?.aggregateId ?? null,
      timestamp: Date.now(),
      traceId,
      source: "template-be-core",
    };

    const useOutbox = options?.useOutbox ?? true;

    // 1. Transactional Outbox: Ghi vào CSDL trước
    if (useOutbox) {
      try {
        let payloadToSave: any = this.encryptSensitivePayloadFields(payload);
        if (payloadToSave && typeof payloadToSave === "object") {
          payloadToSave = { ...payloadToSave, _traceId: traceId };
        }

        const outboxRecord = await this.outboxRepo.create(
          {
            eventType: eventName,
            payload: payloadToSave as unknown as Prisma.InputJsonValue,
            aggregateId: options?.aggregateId ?? null,
          },
          options?.tx,
        );

        envelope.id = outboxRecord.id;

        // Nếu là interactive transaction (options.tx), dừng tại đây — chờ commit để relay sau
        if (options?.tx) {
          return envelope;
        }

        // SEC-58: Khi enqueue vào queue broker ngoại vi (BullMQ/Redis), bản ghi có thể đánh dấu PUBLISHED.
        // Tuy nhiên, khi rơi vào fallback in-memory queue cục bộ, KHÔNG đánh dấu published ngay tại đây
        // mà chờ subscriber thực thi xong trong triggerInMemoryProcessing() để chống mất event khi process crash.
        const destination = await this.enqueueEnvelope(envelope);
        if (destination === "queue") {
          await this.outboxRepo.markPublished(outboxRecord.id).catch(() => {});
        }
        return envelope;
      } catch (err: any) {
        if (options?.tx) {
          throw err;
        }
        console.warn(
          "[EventBus] Failed to write outbox record, fallback direct dispatch:",
          err?.message,
        );
      }
    }

    // 2. Dispatch trực tiếp vào queue
    await this.enqueueEnvelope(envelope);
    return envelope;
  }

  /**
   * Đẩy envelope vào hàng đợi BullMQ hoặc in-memory
   */
  private async enqueueEnvelope(
    envelope: EventEnvelope,
  ): Promise<"queue" | "in_memory"> {
    if (this.isRedisAvailable) {
      try {
        if (
          envConfig.notification.standalone &&
          this.notificationEventNames.has(envelope.name) &&
          this.notificationQueue
        ) {
          await this.notificationQueue.add(envelope.name, envelope, {
            jobId: envelope.id,
          });
          return "queue";
        }

        if (this.queue) {
          await this.queue.add(envelope.name, envelope, {
            jobId: envelope.id,
          });
          return "queue";
        }
      } catch {
        // Fallback in-memory
      }
    }

    // In-memory queue fallback
    this.inMemoryQueue.push({
      id: envelope.id,
      envelope,
      attempts: 0,
    });

    this.triggerInMemoryProcessing();
    return "in_memory";
  }

  private triggerInMemoryProcessing(): void {
    if (this.isProcessingInMemory) return;
    this.isProcessingInMemory = true;

    setImmediate(async () => {
      try {
        while (this.inMemoryQueue.length > 0) {
          const item = this.inMemoryQueue.shift();
          if (!item) break;

          try {
            await this.dispatchDirectly(item.envelope);
            // SEC-58: Đánh dấu outbox event là PUBLISHED chỉ sau khi các subscriber
            // đã hoàn tất xử lý thành công qua dispatchDirectly().
            await this.outboxRepo
              .markPublished(item.envelope.id)
              .catch(() => {});
          } catch (err: any) {
            item.attempts++;
            if (item.attempts >= EVENT_BUS_CONSTANTS.DEFAULT_MAX_ATTEMPTS) {
              await this.moveToDlq(
                item.envelope,
                err?.message || String(err),
                item.attempts,
              );
              await this.outboxRepo
                .markFailed(
                  item.envelope.id,
                  err?.message || String(err),
                  item.attempts,
                )
                .catch(() => {});
            } else {
              // SEC-56: Tách rời (decouple) backoff retry khỏi vòng lặp tuần tự (serial while-loop)
              // nhằm ngăn ngừa Head-of-Line Blocking DoS.
              // Thay vì await sleep đồng bộ chặn đứng toàn bộ các sự kiện lành mạnh phía sau,
              // lên lịch re-enqueue qua setTimeout bất đồng bộ và để vòng lặp tiếp tục xử lý các event tiếp theo ngay lập tức.
              const backoffDelay = Math.min(
                50 * Math.pow(2, item.attempts),
                500,
              );
              const retryTimer = setTimeout(() => {
                this.activeRetryTimers.delete(retryTimer);
                this.inMemoryQueue.push(item);
                this.triggerInMemoryProcessing();
              }, backoffDelay);
              if (typeof retryTimer.unref === "function") {
                retryTimer.unref();
              }
              this.activeRetryTimers.add(retryTimer);
            }
          }
        }
      } finally {
        this.isProcessingInMemory = false;
      }
    });
  }

  /**
   * Xử lý sự kiện trực tiếp tới các consumers kèm bảo vệ Idempotent Consumer
   */
  public async dispatchDirectly(envelope: EventEnvelope): Promise<void> {
    // 1. Kiểm tra tính Idempotent: Nếu eventId đã được xử lý trong vòng 24h thì bỏ qua (SEC-50)
    if (await this.isEventAlreadyProcessed(envelope.id)) {
      console.log(
        `[EventBus] ⏭️ Duplicate event ${envelope.id} skipped (Idempotent protection)`,
      );
      return;
    }

    const handlers = this.handlers.get(envelope.name);
    if (!handlers || handlers.size === 0) {
      // Không có consumer đăng ký cho topic này
      await this.markEventProcessed(envelope.id);
      return;
    }

    // 2. Thực thi toàn bộ consumers song song bên trong Trace Context
    const traceId = envelope.traceId || envelope.id;
    await runWithTraceContext(
      {
        traceId,
        correlationId: traceId,
        source: envelope.source,
        startTime: Date.now(),
      },
      async () => {
        const handlerPromises = Array.from(handlers).map(async (handler) => {
          await handler(envelope);
        });
        await Promise.all(handlerPromises);
      },
    );

    // 3. Đánh dấu đã xử lý thành công
    await this.markEventProcessed(envelope.id);
  }

  /**
   * Kiểm tra xem sự kiện đã từng được xử lý chưa (Idempotency Check)
   * Kết hợp Redis phân tán (multi-pod / replicas) và In-Memory cache fallback (SEC-50).
   */
  public async isEventAlreadyProcessed(eventId: string): Promise<boolean> {
    // 1. Kiểm tra Redis phân tán cho cụm multi-pod / replicas (SEC-50)
    if (this.isRedisAvailable && this.redisConnection) {
      try {
        const cached = await this.redisConnection.get(
          `idempotency:event:${eventId}`,
        );
        if (cached) return true;
      } catch {
        // Fallback sang in-memory nếu Redis trục trặc
      }
    }

    // 2. Fallback sang In-Memory Cache
    const expiresAt = this.processedEventIds.get(eventId);
    if (!expiresAt) return false;
    if (Date.now() > expiresAt) {
      this.processedEventIds.delete(eventId);
      return false;
    }
    return true;
  }

  /**
   * Đánh dấu sự kiện đã được xử lý (Idempotency Record - SEC-50)
   * Sử dụng SET EX trên Redis phân tán và đồng bộ vào bộ nhớ đệm cục bộ.
   */
  public async markEventProcessed(eventId: string): Promise<void> {
    // 1. Ghi nhận vào Redis phân tán với TTL 24 giờ (SEC-50)
    if (this.isRedisAvailable && this.redisConnection) {
      try {
        const ttlSec = Math.max(
          1,
          Math.floor(EVENT_BUS_CONSTANTS.IDEMPOTENCY_TTL_MS / 1000),
        );
        await this.redisConnection.set(
          `idempotency:event:${eventId}`,
          "1",
          "EX",
          ttlSec,
        );
      } catch {
        // Fallback
      }
    }

    // 2. Ghi nhận vào In-Memory Cache
    if (this.processedEventIds.size >= 10000) {
      const now = Date.now();
      for (const [k, exp] of this.processedEventIds.entries()) {
        if (exp <= now) this.processedEventIds.delete(k);
      }
      if (this.processedEventIds.size >= 10000) {
        const firstKey = this.processedEventIds.keys().next().value;
        if (firstKey) this.processedEventIds.delete(firstKey);
      }
    }

    this.processedEventIds.set(
      eventId,
      Date.now() + EVENT_BUS_CONSTANTS.IDEMPOTENCY_TTL_MS,
    );
  }

  /**
   * Nguyên tử hóa kiểm tra và ghi nhận sự kiện qua Redis SET NX EX (Atomic Idempotent Claim - SEC-50).
   * Trả về true nếu sự kiện là mới (khóa thành công), false nếu sự kiện đã tồn tại (duplicate).
   */
  public async tryAcquireEventLock(
    eventId: string,
    ttlMs: number = EVENT_BUS_CONSTANTS.IDEMPOTENCY_TTL_MS,
  ): Promise<boolean> {
    if (this.isRedisAvailable && this.redisConnection) {
      try {
        const ttlSec = Math.max(1, Math.floor(ttlMs / 1000));
        const res = await this.redisConnection.set(
          `idempotency:event:${eventId}`,
          "1",
          "EX",
          ttlSec,
          "NX",
        );
        if (res === "OK") {
          this.processedEventIds.set(eventId, Date.now() + ttlMs);
          return true;
        }
        return false;
      } catch {
        // Fallback sang in-memory
      }
    }

    if (await this.isEventAlreadyProcessed(eventId)) {
      return false;
    }
    await this.markEventProcessed(eventId);
    return true;
  }

  /**
   * Đưa sự kiện vào Dead-Letter Queue (DLQ) khi vượt quá số lần thử tối đa
   */
  public async moveToDlq(
    envelope: EventEnvelope,
    error: string,
    attempts: number,
  ): Promise<void> {
    const record: DlqRecord = {
      envelope,
      error,
      failedAt: Date.now(),
      attempts,
      status: "PENDING",
    };

    this.dlqEvents.push(record);
    if (this.dlqEvents.length > 500) {
      this.dlqEvents.shift();
    }

    if (this.isRedisAvailable && this.dlqQueue) {
      try {
        await this.dlqQueue.add("poison-event", record, {
          jobId: `dlq-${envelope.id}`,
        });
      } catch {
        // Fallback in-memory DLQ
      }
    }

    console.error(
      `[EventBus] ☠️ Event moved to DLQ: [${envelope.name}] ID: ${envelope.id} - Reason: ${error}`,
    );
  }

  /**
   * Transactional Outbox Relay:
   * Quét các bản ghi PENDING trong bảng outbox_events, gửi tới consumers và cập nhật PUBLISHED.
   * Đây là hạt nhân của Transactional Outbox Pattern chống mất mát sự kiện khi hệ thống crash.
   */
  public async relayPendingOutboxEvents(
    batchSize: number = EVENT_BUS_CONSTANTS.OUTBOX_BATCH_SIZE,
  ): Promise<number> {
    try {
      const pendingRecords =
        await this.outboxRepo.claimPendingEvents(batchSize);
      if (!pendingRecords || pendingRecords.length === 0) {
        return 0;
      }

      let publishedCount = 0;

      for (const record of pendingRecords) {
        try {
          const decryptedPayload = this.decryptSensitivePayloadFields(
            record.payload,
          );

          const envelope: EventEnvelope = {
            id: record.id,
            name: record.eventType as EventName,
            payload: decryptedPayload,
            aggregateId: record.aggregateId,
            timestamp: record.createdAt.getTime(),
            traceId:
              (decryptedPayload as any)?._traceId ||
              (decryptedPayload as any)?.traceId ||
              record.id,
            source: "template-be-outbox-relay",
          };

          // Nếu tiến trình hiện tại có handler cho sự kiện này -> dispatch trực tiếp
          if (
            this.handlers.has(record.eventType) &&
            (this.handlers.get(record.eventType)?.size || 0) > 0
          ) {
            await this.dispatchDirectly(envelope);
          } else {
            // Ngược lại (ví dụ worker relay sự kiện của satellite notification-service):
            // Enqueue vào BullMQ để notification-service tiêu thụ
            await this.enqueueEnvelope(envelope);
          }

          await this.outboxRepo.markPublished(record.id);
          publishedCount++;
        } catch (err: any) {
          await this.outboxRepo.markFailed(
            record.id,
            err?.message || String(err),
            EVENT_BUS_CONSTANTS.DEFAULT_MAX_ATTEMPTS,
          );
        }
      }

      return publishedCount;
    } catch (err: any) {
      console.warn("[EventBus] Outbox relay error:", err?.message || err);
      return 0;
    }
  }

  /**
   * Mã hóa các trường dữ liệu nhạy cảm (tokens, keys, presigned URLs - SEC-47) trong payload
   * trước khi lưu vào bảng outbox_events nhằm chống rò rỉ plain-text trong CSDL.
   */
  public encryptSensitivePayloadFields<T>(payload: T): T {
    if (!payload || typeof payload !== "object") return payload;
    const clone = { ...(payload as any) };

    for (const field of SENSITIVE_OUTBOX_FIELDS) {
      if (
        field in clone &&
        typeof clone[field] === "string" &&
        !clone[field].startsWith("enc:")
      ) {
        try {
          clone[field] = `enc:${encryptSecret(clone[field])}`;
        } catch {
          // Giữ nguyên nếu chưa có master key trong môi trường test
        }
      }
    }

    return clone as T;
  }

  /**
   * Giải mã các trường dữ liệu nhạy cảm khi đọc từ bảng outbox_events để chuyển tiếp tới subscribers
   */
  public decryptSensitivePayloadFields<T>(payload: T): T {
    if (!payload || typeof payload !== "object") return payload;
    const clone = { ...(payload as any) };

    for (const field of SENSITIVE_OUTBOX_FIELDS) {
      if (
        field in clone &&
        typeof clone[field] === "string" &&
        clone[field].startsWith("enc:")
      ) {
        try {
          clone[field] = decryptSecret(clone[field].slice(4));
        } catch {
          // Giữ nguyên nếu giải mã thất bại
        }
      }
    }

    return clone as T;
  }

  /**
   * Các phương thức phục vụ kiểm thử và quan sát
   */
  public get isConnected(): boolean {
    return this.isRedisAvailable;
  }

  public get processedCacheSize(): number {
    return this.processedEventIds.size;
  }

  public getDlqEvents(): DlqRecord[] {
    return [...this.dlqEvents];
  }

  public markDlqReprocessed(eventId: string): boolean {
    const record = this.dlqEvents.find((r) => r.envelope.id === eventId);
    if (record) {
      record.status = "REPROCESSED";
      record.reprocessedAt = Date.now();
      return true;
    }
    return false;
  }

  public removeDlqRecord(eventId: string): boolean {
    const index = this.dlqEvents.findIndex((r) => r.envelope.id === eventId);
    if (index !== -1) {
      this.dlqEvents.splice(index, 1);
      return true;
    }
    return false;
  }

  public clearDlq(): void {
    this.dlqEvents = [];
  }

  public async clearProcessedCache(): Promise<void> {
    this.processedEventIds.clear();
    if (this.isRedisAvailable && this.redisConnection) {
      try {
        const keys = await this.redisConnection.keys("idempotency:event:*");
        if (keys && keys.length > 0) {
          await this.redisConnection.del(...keys);
        }
      } catch {
        // Ignore
      }
    }
  }

  public getSubscriberCount(eventName: string): number {
    return this.handlers.get(eventName)?.size ?? 0;
  }

  public async close(): Promise<void> {
    this.handlers.clear();
    for (const timer of this.activeRetryTimers) {
      clearTimeout(timer);
    }
    this.activeRetryTimers.clear();
    this.inMemoryQueue = [];
    if (this.queue) {
      await this.queue.close().catch(() => {});
    }
    if (this.notificationQueue) {
      await this.notificationQueue.close().catch(() => {});
    }
    if (this.dlqQueue) {
      await this.dlqQueue.close().catch(() => {});
    }
    if (this.redisConnection) {
      this.redisConnection.disconnect();
    }
  }
}

export const eventBus = new EventBusService();
