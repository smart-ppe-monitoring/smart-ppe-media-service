import { Prisma } from "@prisma/client-media";
import { prisma } from "../../database/prisma.client";
import { FileQueryDto } from "./file.dto";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
} from "../../common/helpers/pagination.helper";
import { buildTsQuery } from "../../common/helpers/fts.helper";

const fileSelect = {
  id: true,
  userId: true,
  originalName: true,
  fileName: true,
  mimeType: true,
  size: true,
  bucketKey: true,
  folder: true,
  isPublic: true,
  isConfirmed: true,
  metadata: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.FileRecordSelect;

/**
 * Biểu thức tính tsvector chuẩn hóa phục vụ Full-Text Search trên bảng file_records.
 * Biểu thức này khớp chính xác 100% với GIN index `idx_file_records_fts` trong CSDL PostgreSQL (SEC-26),
 * cho phép PostgreSQL thực thi Bitmap Index Scan thay vì Seq Scan trên toàn bộ bảng.
 */
export const FILE_RECORDS_FTS_VECTOR_EXPR = Prisma.sql`to_tsvector('simple', coalesce(f.original_name, '') || ' ' || coalesce(f.file_name, '') || ' ' || coalesce(f.folder, ''))`;

export class FileRepository {
  private db: any;

  constructor(dbClient: any = prisma) {
    this.db = dbClient;
  }

  async create(data: {
    userId?: string | null;
    originalName: string;
    fileName: string;
    mimeType: string;
    size?: number | bigint;
    bucketKey: string;
    folder?: string;
    isPublic?: boolean;
    metadata?: Prisma.InputJsonValue;
  }) {
    const record = await this.db.fileRecord.create({
      data: {
        userId: data.userId,
        originalName: data.originalName,
        fileName: data.fileName,
        mimeType: data.mimeType,
        size: data.size !== undefined ? BigInt(data.size) : BigInt(0),
        bucketKey: data.bucketKey,
        folder: data.folder ?? "general",
        isPublic: data.isPublic ?? false,
        isConfirmed: false,
        metadata: data.metadata,
      },
      select: fileSelect,
    });
    return { ...record, size: Number(record.size) };
  }

  async findById(id: string) {
    const record = await this.db.fileRecord.findFirst({
      where: { id, deletedAt: null },
      select: fileSelect,
    });
    return record ? { ...record, size: Number(record.size) } : null;
  }

  async findByBucketKey(bucketKey: string) {
    const record = await this.db.fileRecord.findUnique({
      where: { bucketKey },
      select: fileSelect,
    });
    return record ? { ...record, size: Number(record.size) } : null;
  }

  async confirmUpload(id: string, size?: number | bigint) {
    const updated = await this.db.fileRecord.update({
      where: { id },
      data: {
        isConfirmed: true,
        ...(size !== undefined ? { size: BigInt(size) } : {}),
      },
      select: fileSelect,
    });
    return { ...updated, size: Number(updated.size) };
  }

  async findAll(
    query: FileQueryDto = {},
    currentUserId?: string,
    canManageAll = false,
  ) {
    const {
      folder,
      isPublic,
      mimeType,
      search,
      userId,
      sortBy = "createdAt",
      order = "desc",
      page = 1,
      limit = 20,
    } = query || {};

    let userFilter: Prisma.FileRecordWhereInput = {};
    if (canManageAll) {
      if (userId) userFilter = { userId };
    } else {
      userFilter = currentUserId
        ? { OR: [{ userId: currentUserId }, { isPublic: true }] }
        : { isPublic: true };
    }

    const conditions: Prisma.FileRecordWhereInput[] = [
      { deletedAt: null, isConfirmed: true },
      userFilter,
    ];

    if (folder) {
      conditions.push({ folder });
    }
    if (isPublic !== undefined) {
      conditions.push({ isPublic });
    }
    if (mimeType) {
      conditions.push({ mimeType: { startsWith: mimeType } });
    }
    if (search) {
      conditions.push({
        OR: [
          { originalName: { contains: search, mode: "insensitive" } },
          { fileName: { contains: search, mode: "insensitive" } },
        ],
      });
    }

    const where: Prisma.FileRecordWhereInput = {
      AND: conditions,
    };

    const {
      skip,
      take,
      page: safePage,
      limit: safeLimit,
    } = calculatePaginationSkip(page, limit);

    const SORT_MAP: Record<string, Prisma.FileRecordOrderByWithRelationInput> =
      {
        createdAt: { createdAt: order },
        fileName: { fileName: order },
        size: { size: order },
      };
    const orderBy = SORT_MAP[sortBy] ?? { createdAt: order };

    const [data, total] = await prisma.$transaction([
      prisma.fileRecord.findMany({
        where,
        select: fileSelect,
        orderBy,
        skip,
        take,
      }),
      prisma.fileRecord.count({ where }),
    ]);

    const mappedData = data.map((f) => ({
      ...f,
      size: Number(f.size),
    }));

    return {
      data: mappedData,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  /**
   * Tìm kiếm tệp tin bằng PostgreSQL Full-Text Search (tsvector, tsquery & GIN index)
   * Tự động xếp hạng độ liên quan qua hàm ts_rank
   */
  async searchFts(
    query: FileQueryDto,
    currentUserId?: string,
    canManageAll?: boolean,
  ) {
    const search = query.search?.trim();
    if (!search) {
      return this.findAll(query, currentUserId, canManageAll);
    }

    const tsQuery = buildTsQuery(search, "prefix");
    if (!tsQuery) {
      return this.findAll(query, currentUserId, canManageAll);
    }

    const {
      skip,
      take,
      page: safePage,
      limit: safeLimit,
    } = calculatePaginationSkip(query.page, query.limit);

    const whereConditions: Prisma.Sql[] = [
      Prisma.sql`f.deleted_at IS NULL`,
      Prisma.sql`f.is_confirmed = true`,
      Prisma.sql`${FILE_RECORDS_FTS_VECTOR_EXPR} @@ to_tsquery('simple', ${tsQuery})`,
    ];

    if (!canManageAll) {
      if (currentUserId) {
        whereConditions.push(
          Prisma.sql`(f.is_public = true OR f.user_id = ${currentUserId}::uuid)`,
        );
      } else {
        whereConditions.push(Prisma.sql`f.is_public = true`);
      }
    } else if (query.userId) {
      whereConditions.push(Prisma.sql`f.user_id = ${query.userId}::uuid`);
    }

    if (query.folder) {
      whereConditions.push(Prisma.sql`f.folder = ${query.folder}`);
    }

    if (query.isPublic !== undefined) {
      whereConditions.push(Prisma.sql`f.is_public = ${query.isPublic}`);
    }

    if (query.mimeType) {
      whereConditions.push(
        Prisma.sql`f.mime_type LIKE ${query.mimeType + "%"}`,
      );
    }

    const whereClause = Prisma.sql`WHERE ${Prisma.join(whereConditions, " AND ")}`;

    const [rawFiles, countResult] = await prisma.$transaction([
      prisma.$queryRaw<
        Array<{
          id: string;
          user_id: string | null;
          original_name: string;
          file_name: string;
          mime_type: string;
          size: number;
          bucket_key: string;
          folder: string;
          is_public: boolean;
          is_confirmed: boolean;
          metadata: unknown;
          created_at: Date;
          updated_at: Date;
          rank: number;
        }>
      >`
        SELECT
          f.id, f.user_id, f.original_name, f.file_name, f.mime_type,
          f.size, f.bucket_key, f.folder, f.is_public, f.is_confirmed,
          f.metadata, f.created_at, f.updated_at,
          ts_rank(${FILE_RECORDS_FTS_VECTOR_EXPR}, to_tsquery('simple', ${tsQuery})) as rank
        FROM file_records f
        ${whereClause}
        ORDER BY rank DESC, f.created_at DESC
        OFFSET ${skip}
        LIMIT ${take}
      `,
      prisma.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint as count
        FROM file_records f
        ${whereClause}
      `,
    ]);

    const total = Number(countResult[0]?.count ?? 0);
    const data = rawFiles.map((f) => ({
      id: f.id,
      userId: f.user_id,
      originalName: f.original_name,
      fileName: f.file_name,
      mimeType: f.mime_type,
      size: f.size,
      bucketKey: f.bucket_key,
      folder: f.folder,
      isPublic: f.is_public,
      isConfirmed: f.is_confirmed,
      metadata: f.metadata,
      createdAt: f.created_at,
      updatedAt: f.updated_at,
      user: f.user_id ? { id: f.user_id, fullName: null } : null,
    }));

    return {
      data,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  /**
   * Đảm bảo chỉ mục GIN cho Full-Text Search tồn tại trên bảng file_records (SEC-26).
   */
  async ensureFtsIndex(): Promise<void> {
    try {
      await prisma.$executeRawUnsafe(`
        CREATE INDEX IF NOT EXISTS "idx_file_records_fts" ON "file_records" USING gin (
          to_tsvector('simple', coalesce("original_name", '') || ' ' || coalesce("file_name", '') || ' ' || coalesce("folder", ''))
        );
      `);
    } catch {
      // Ignored when offline or in test environments
    }
  }

  async delete(id: string) {
    return prisma.fileRecord.update({
      where: { id },
      data: {
        deletedAt: new Date(),
      },
      select: fileSelect,
    });
  }

  createAuditLog(data: {
    actorId?: string;
    action: string;
    targetType: string;
    targetId: string;
    details?: Record<string, unknown> | null;
    ipAddress?: string;
    userAgent?: string;
  }) {
    return prisma.auditLog.create({
      data: {
        actorId: data.actorId,
        action: data.action,
        targetType: data.targetType,
        targetId: data.targetId,
        details: (data.details ?? Prisma.JsonNull) as Prisma.InputJsonValue,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      },
    });
  }

  async createDirectFile(data: {
    userId?: string | null;
    originalName: string;
    fileName: string;
    mimeType: string;
    size: number | bigint;
    bucketKey: string;
    folder?: string;
    isPublic?: boolean;
    metadata?: Prisma.InputJsonValue;
  }) {
    const record = await this.db.fileRecord.create({
      data: {
        userId: data.userId,
        originalName: data.originalName,
        fileName: data.fileName,
        mimeType: data.mimeType,
        size: BigInt(data.size),
        bucketKey: data.bucketKey,
        folder: data.folder ?? "general",
        isPublic: data.isPublic ?? false,
        isConfirmed: true,
        metadata: data.metadata,
      },
      select: fileSelect,
    });
    return { ...record, size: Number(record.size) };
  }

  findUnconfirmedOlderThan(cutoff: Date, limit = 100) {
    return prisma.fileRecord.findMany({
      where: {
        isConfirmed: false,
        createdAt: { lt: cutoff },
        deletedAt: null,
      },
      take: limit,
      select: {
        id: true,
        bucketKey: true,
        createdAt: true,
      },
    });
  }

  findSoftDeletedOlderThan(cutoff: Date, limit = 100) {
    return prisma.fileRecord.findMany({
      where: {
        deletedAt: { not: null, lt: cutoff },
      },
      take: limit,
      select: {
        id: true,
        bucketKey: true,
        deletedAt: true,
      },
    });
  }

  /**
   * Đánh dấu các bản ghi là CLEANUP_PENDING (soft-delete / cô lập) trong CSDL trước khi xóa blob lưu trữ vật lý (SEC-41).
   * Ngăn chặn người dùng đọc hoặc kích hoạt bản ghi trong thời gian dọn dẹp và chống mất tính nhất quán nếu tiến trình bị gián đoạn.
   */
  markCleanupPending(ids: string[]) {
    if (!ids || ids.length === 0) return Promise.resolve({ count: 0 });
    return prisma.fileRecord.updateMany({
      where: { id: { in: ids } },
      data: {
        deletedAt: new Date(),
      },
    });
  }

  hardDeleteMany(ids: string[]) {
    if (!ids || ids.length === 0) return Promise.resolve({ count: 0 });
    return prisma.fileRecord.deleteMany({
      where: { id: { in: ids } },
    });
  }
}

export const fileRepository = new FileRepository();
