import { Prisma } from "@prisma/client";
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
  user: {
    select: {
      id: true,
      fullName: true,
    },
  },
} satisfies Prisma.FileRecordSelect;

export class FileRepository {
  create(data: {
    userId?: string | null;
    originalName: string;
    fileName: string;
    mimeType: string;
    size?: number;
    bucketKey: string;
    folder?: string;
    isPublic?: boolean;
    metadata?: Prisma.InputJsonValue;
  }) {
    return prisma.fileRecord.create({
      data: {
        userId: data.userId,
        originalName: data.originalName,
        fileName: data.fileName,
        mimeType: data.mimeType,
        size: data.size ?? 0,
        bucketKey: data.bucketKey,
        folder: data.folder ?? "general",
        isPublic: data.isPublic ?? false,
        isConfirmed: false,
        metadata: data.metadata,
      },
      select: fileSelect,
    });
  }

  findById(id: string) {
    return prisma.fileRecord.findFirst({
      where: { id, deletedAt: null },
      select: fileSelect,
    });
  }

  findByBucketKey(bucketKey: string) {
    return prisma.fileRecord.findUnique({
      where: { bucketKey },
      select: fileSelect,
    });
  }

  confirmUpload(id: string, size?: number) {
    return prisma.fileRecord.update({
      where: { id },
      data: {
        isConfirmed: true,
        ...(size !== undefined ? { size } : {}),
      },
      select: fileSelect,
    });
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

    return {
      data,
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
      Prisma.sql`to_tsvector('simple', coalesce(f.original_name, '') || ' ' || coalesce(f.file_name, '') || ' ' || coalesce(f.folder, '')) @@ to_tsquery('simple', ${tsQuery})`,
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
          user_full_name: string | null;
          rank: number;
        }>
      >`
        SELECT
          f.id, f.user_id, f.original_name, f.file_name, f.mime_type,
          f.size, f.bucket_key, f.folder, f.is_public, f.is_confirmed,
          f.metadata, f.created_at, f.updated_at,
          u.full_name as user_full_name,
          ts_rank(to_tsvector('simple', coalesce(f.original_name, '') || ' ' || coalesce(f.file_name, '') || ' ' || coalesce(f.folder, '')), to_tsquery('simple', ${tsQuery})) as rank
        FROM file_records f
        LEFT JOIN users u ON f.user_id = u.id
        ${whereClause}
        ORDER BY rank DESC, f.created_at DESC
        OFFSET ${skip}
        LIMIT ${take}
      `,
      prisma.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint as count
        FROM file_records f
        LEFT JOIN users u ON f.user_id = u.id
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
      user: f.user_id ? { id: f.user_id, fullName: f.user_full_name } : null,
    }));

    return {
      data,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
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

  createDirectFile(data: {
    userId?: string | null;
    originalName: string;
    fileName: string;
    mimeType: string;
    size: number;
    bucketKey: string;
    folder?: string;
    isPublic?: boolean;
    metadata?: Prisma.InputJsonValue;
  }) {
    return prisma.fileRecord.create({
      data: {
        userId: data.userId,
        originalName: data.originalName,
        fileName: data.fileName,
        mimeType: data.mimeType,
        size: data.size,
        bucketKey: data.bucketKey,
        folder: data.folder ?? "general",
        isPublic: data.isPublic ?? false,
        isConfirmed: true,
        metadata: data.metadata,
      },
      select: fileSelect,
    });
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

  hardDeleteMany(ids: string[]) {
    if (!ids || ids.length === 0) return Promise.resolve({ count: 0 });
    return prisma.fileRecord.deleteMany({
      where: { id: { in: ids } },
    });
  }
}

export const fileRepository = new FileRepository();
