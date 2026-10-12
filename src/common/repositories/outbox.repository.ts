import { Prisma, PrismaClient } from "@prisma/client";
import { prisma } from "../../database/prisma.client";
import {
  OUTBOX_STATUS,
  OutboxStatus,
  EVENT_BUS_CONSTANTS,
} from "../constants/event.constant";

export interface CreateOutboxEventParams {
  eventType: string;
  payload: Prisma.InputJsonValue;
  aggregateId?: string | null;
}

export interface OutboxRecord {
  id: string;
  eventType: string;
  payload: Prisma.JsonValue;
  aggregateId: string | null;
  status: string;
  attempts: number;
  lastError: string | null;
  publishedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export class OutboxRepository {
  private readonly db: PrismaClient;

  constructor(db?: PrismaClient) {
    this.db = db || prisma;
  }

  /**
   * Tạo bản ghi outbox event mới.
   * Hỗ trợ truyền `tx` (Prisma.TransactionClient) để đảm bảo tính nguyên tử
   * cùng với transaction nghiệp vụ (Transactional Outbox Pattern).
   */
  async create(
    data: CreateOutboxEventParams,
    tx?: Prisma.TransactionClient,
  ): Promise<OutboxRecord> {
    const client = tx || this.db;
    return client.outboxEvent.create({
      data: {
        eventType: data.eventType,
        payload: data.payload,
        aggregateId: data.aggregateId ?? null,
        status: OUTBOX_STATUS.PENDING,
        attempts: 0,
      },
    });
  }

  /**
   * Lấy danh sách các sự kiện đang chờ xuất bản với atomic update & lock
   * (UPDATE outbox_events SET status = 'PROCESSING' WHERE id IN (...) RETURNING ...)
   * Triệt tiêu hoàn toàn race condition trùng lặp khi chạy nhiều server pods/instances.
   */
  async claimPendingEvents(batchSize: number = 50): Promise<OutboxRecord[]> {
    const events = await this.db.$queryRaw<
      Array<{
        id: string;
        event_type: string;
        payload: any;
        aggregate_id: string | null;
        status: string;
        attempts: number;
        last_error: string | null;
        published_at: Date | null;
        created_at: Date;
        updated_at: Date;
      }>
    >`
      UPDATE outbox_events
      SET status = ${OUTBOX_STATUS.PROCESSING}, updated_at = NOW()
      WHERE id IN (
        SELECT id FROM outbox_events
        WHERE (
          status = ${OUTBOX_STATUS.PENDING}
          OR (status = ${OUTBOX_STATUS.PROCESSING} AND updated_at < NOW() - INTERVAL '5 minutes')
        )
        AND attempts < ${EVENT_BUS_CONSTANTS.DEFAULT_MAX_ATTEMPTS}
        ORDER BY created_at ASC
        LIMIT ${batchSize}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING
        id,
        event_type,
        payload,
        aggregate_id,
        status,
        attempts,
        last_error,
        published_at,
        created_at,
        updated_at;
    `;

    return events.map((e) => ({
      id: e.id,
      eventType: e.event_type,
      payload: e.payload,
      aggregateId: e.aggregate_id,
      status: e.status,
      attempts: e.attempts,
      lastError: e.last_error,
      publishedAt: e.published_at,
      createdAt: e.created_at,
      updatedAt: e.updated_at,
    }));
  }

  /**
   * Dọn dẹp các sự kiện đã PUBLISHED cũ hơn thời điểm chỉ định
   */
  async deletePublishedOlderThan(cutoffDate: Date): Promise<number> {
    const result = await this.db.outboxEvent.deleteMany({
      where: {
        status: OUTBOX_STATUS.PUBLISHED,
        publishedAt: { lt: cutoffDate },
      },
    });
    return result.count;
  }

  /**
   * Cập nhật trạng thái sự kiện sang PUBLISHED khi đã gửi thành công tới Event Bus
   */
  async markPublished(
    id: string,
    tx?: Prisma.TransactionClient,
  ): Promise<void> {
    const client = tx || this.db;
    await client.outboxEvent.update({
      where: { id },
      data: {
        status: OUTBOX_STATUS.PUBLISHED,
        publishedAt: new Date(),
        lastError: null,
      },
    });
  }

  /**
   * Cập nhật lỗi và tăng số lần thử khi gửi thất bại
   */
  async markFailed(
    id: string,
    errorMessage: string,
    maxAttempts: number = 5,
    tx?: Prisma.TransactionClient,
  ): Promise<void> {
    const client = tx || this.db;
    const existing = await client.outboxEvent.findUnique({
      where: { id },
      select: { attempts: true },
    });

    const nextAttempts = (existing?.attempts ?? 0) + 1;
    const nextStatus: OutboxStatus =
      nextAttempts >= maxAttempts
        ? OUTBOX_STATUS.FAILED
        : OUTBOX_STATUS.PENDING;

    await client.outboxEvent.update({
      where: { id },
      data: {
        status: nextStatus,
        attempts: nextAttempts,
        lastError: errorMessage,
      },
    });
  }

  /**
   * Tìm kiếm event theo ID
   */
  async findById(id: string): Promise<OutboxRecord | null> {
    return this.db.outboxEvent.findUnique({
      where: { id },
    });
  }

  /**
   * Đếm số lượng sự kiện đang chờ gửi
   */
  async countPending(): Promise<number> {
    return this.db.outboxEvent.count({
      where: { status: OUTBOX_STATUS.PENDING },
    });
  }
}

export const outboxRepository = new OutboxRepository();
