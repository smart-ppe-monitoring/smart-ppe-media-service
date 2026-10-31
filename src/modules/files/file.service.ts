import path from "node:path";
import { uuidv7 } from "uuidv7";
import { Prisma } from "@prisma/client-media";
import { FileRepository, fileRepository } from "./file.repository";
import { R2Service } from "../../common/services/r2.service";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
  SYSTEM_TARGET_ID,
} from "../../common/constants/audit-log.constant";
import {
  STORAGE_CONFIG_KEYS,
  DEFAULT_ALLOWED_MIME_TYPES,
} from "../../common/constants/system-config.constant";
import { r2Config } from "../../config/r2.config";
import {
  RequestUploadUrlDto,
  UploadUrlResponseDto,
  ConfirmUploadDto,
  FileQueryDto,
  FileResponseDto,
  DownloadUrlResponseDto,
  DirectImageUploadDto,
  ImageTransformDto,
  CleanupResultDto,
} from "./file.dto";
import {
  eventBus,
  EventBusService,
} from "../../common/services/event-bus.service";
import { EVENT_NAMES } from "../../common/constants/event.constant";
import {
  ImageProcessingService,
  imageProcessingService,
} from "../../common/services/image-processing.service";
import {
  IMAGE_FORMAT,
  MEDIA_FOLDER,
  MEDIA_LIMITS,
} from "../../common/constants/media.constant";

export class FileService {
  private readonly repository: FileRepository;
  private readonly r2Service: R2Service;
  private readonly eventBus: EventBusService;
  private readonly imageProcessor: ImageProcessingService;

  constructor(
    repository?: FileRepository,
    r2Service?: R2Service,
    eventBusService?: EventBusService,
    imageProcessor?: ImageProcessingService,
  ) {
    this.repository = repository || fileRepository;
    this.r2Service = r2Service || new R2Service();
    this.eventBus = eventBusService || eventBus;
    this.imageProcessor = imageProcessor || imageProcessingService;
  }

  private async resolveEffectivePermissions(
    userId?: string,
    permissions?: string[],
  ): Promise<string[]> {
    if (permissions && permissions.length > 0) {
      return permissions;
    }
    if (userId) {
      return this.getUserPermissions(userId);
    }
    return [];
  }

  private async getUserPermissions(_userId: string): Promise<string[]> {
    return [];
  }

  private isMimeTypeAllowed(
    mimeType: string,
    allowedPatterns: readonly string[] | string[],
  ): boolean {
    const lowerMime = mimeType.toLowerCase();
    return allowedPatterns.some((pattern) => {
      const lowerPattern = pattern.toLowerCase();
      if (lowerPattern.endsWith("/*")) {
        const prefix = lowerPattern.slice(0, -1);
        return lowerMime.startsWith(prefix);
      }
      if (lowerPattern.endsWith(".*")) {
        const prefix = lowerPattern.slice(0, -1);
        return lowerMime.startsWith(prefix);
      }
      return lowerMime === lowerPattern;
    });
  }

  private sanitizeFilename(filename: string): string {
    const ext = path.extname(filename).toLowerCase();
    const basename = path
      .basename(filename, ext)
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "");
    return `${basename || "file"}_${uuidv7().replace(/-/g, "").slice(0, 16)}${ext}`;
  }

  async requestUploadUrl(
    data: RequestUploadUrlDto,
    userId?: string,
    permissions?: string[],
    metadata?: { ipAddress?: string; userAgent?: string },
  ): Promise<UploadUrlResponseDto> {
    // Kiểm tra quyền FILE_UPLOAD nếu là người dùng đã đăng nhập
    if (userId) {
      const userPermissions = await this.resolveEffectivePermissions(
        userId,
        permissions,
      );
      const canUpload =
        userPermissions.includes(PERMISSIONS.FILE_UPLOAD) ||
        userPermissions.includes(PERMISSIONS.FILE_MANAGE);
      if (!canUpload) {
        throw new AppError(
          "Bạn không có quyền tải tệp lên hệ thống",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    // 1. Kiểm tra giới hạn dung lượng động
    const maxFileSizeMb = 100;
    const maxSizeBytes = maxFileSizeMb * 1024 * 1024;
    if (data.size && data.size > maxSizeBytes) {
      throw new AppError(
        `Dung lượng tệp vượt quá giới hạn cấu hình cho phép (${maxFileSizeMb}MB)`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    // 2. Kiểm tra định dạng MIME type cho phép
    const allowedMimeTypes = [...DEFAULT_ALLOWED_MIME_TYPES];
    if (!this.isMimeTypeAllowed(data.mimeType, allowedMimeTypes)) {
      throw new AppError(
        `Định dạng tệp '${data.mimeType}' không được hệ thống hỗ trợ`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    // 3. Thời gian sống của link upload
    const expiresIn = r2Config.presignedUrlExpiresIn;

    const sanitizedName = this.sanitizeFilename(data.fileName);
    const folder = data.folder || "general";
    const bucketKey = `${folder}/${userId || "anonymous"}/${uuidv7()}_${sanitizedName}`;

    const fileRecord = await this.repository.create({
      userId,
      originalName: data.fileName,
      fileName: sanitizedName,
      mimeType: data.mimeType,
      size: data.size,
      bucketKey,
      folder,
      isPublic: data.isPublic ?? false,
      metadata: (data.metadata ?? Prisma.JsonNull) as Prisma.InputJsonValue,
    });

    const uploadUrl = await this.r2Service.getPresignedUploadUrl(
      bucketKey,
      data.mimeType,
      expiresIn,
    );

    // Event-Driven Backbone: Publish file.uploaded_unconfirmed event
    const uploadExpiresAt = new Date(
      Date.now() + expiresIn * 1000,
    ).toISOString();
    await this.eventBus
      .publish(EVENT_NAMES.FILE_UPLOADED_UNCONFIRMED, {
        fileId: fileRecord.id,
        key: bucketKey,
        bucket: r2Config.bucketName || "template-be-bucket",
        expiresAt: uploadExpiresAt,
      })
      .catch((err) => {
        console.warn(
          "[FileService] Failed to publish file.uploaded_unconfirmed event:",
          err?.message || err,
        );
      });

    await this.repository.createAuditLog({
      actorId: userId,
      action: AUDIT_ACTION.REQUEST_FILE_UPLOAD,
      targetType: AUDIT_TARGET_TYPE.FILE,
      targetId: fileRecord.id,
      details: {
        bucketKey,
        originalName: data.fileName,
        isPublic: data.isPublic,
      },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });

    return {
      fileId: fileRecord.id,
      uploadUrl,
      bucketKey,
      isPublic: fileRecord.isPublic,
      expiresIn,
    };
  }

  async confirmUpload(
    id: string,
    data: ConfirmUploadDto = {},
    userId?: string,
    permissions?: string[],
    metadata?: { ipAddress?: string; userAgent?: string },
  ): Promise<FileResponseDto> {
    const file = await this.repository.findById(id);
    if (!file) {
      throw new AppError("Tệp không tồn tại", 404, ERROR_CODE.FILE_NOT_FOUND);
    }

    if (file.isConfirmed) {
      throw new AppError(
        "Tệp này đã được xác nhận tải lên trước đó",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    const userPermissions = await this.resolveEffectivePermissions(
      userId,
      permissions,
    );
    const canManageAll = userPermissions.includes(PERMISSIONS.FILE_MANAGE);
    // CRIT-01 Fix: File anonymous (userId === null) không được tự động match với caller; chỉ admin (FILE_MANAGE) mới có thể xác nhận
    const isOwner = Boolean(file.userId && userId && file.userId === userId);

    if (!isOwner && !canManageAll) {
      throw new AppError(
        "Bạn không có quyền xác nhận tệp này",
        403,
        ERROR_CODE.FORBIDDEN,
      );
    }

    // Kiểm tra dung lượng xác nhận với cấu hình hệ thống
    if (data?.size) {
      const maxFileSizeMb = 100;
      const maxSizeBytes = maxFileSizeMb * 1024 * 1024;
      if (data.size > maxSizeBytes) {
        throw new AppError(
          `Dung lượng tệp vượt quá giới hạn cấu hình cho phép (${maxFileSizeMb}MB)`,
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
    }

    const updated = await this.repository.confirmUpload(id, data?.size);

    await this.repository.createAuditLog({
      actorId: userId,
      action: AUDIT_ACTION.CONFIRM_FILE_UPLOAD,
      targetType: AUDIT_TARGET_TYPE.FILE,
      targetId: id,
      details: { bucketKey: file.bucketKey, size: data.size },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });

    return {
      ...updated,
      url: updated.isPublic
        ? this.r2Service.getPublicUrl(updated.bucketKey)
        : undefined,
    };
  }

  async getFileById(
    id: string,
    userId?: string,
    permissions?: string[],
  ): Promise<FileResponseDto> {
    const file = await this.repository.findById(id);
    if (!file) {
      throw new AppError("Tệp không tồn tại", 404, ERROR_CODE.FILE_NOT_FOUND);
    }

    if (!file.isPublic) {
      if (!userId) {
        throw new AppError(
          "Vui lòng đăng nhập để truy cập tệp riêng tư này",
          401,
          ERROR_CODE.UNAUTHORIZED,
        );
      }

      const userPermissions = await this.resolveEffectivePermissions(
        userId,
        permissions,
      );
      const canManageAll = userPermissions.includes(PERMISSIONS.FILE_MANAGE);
      const isOwner = file.userId === userId;

      if (!isOwner && !canManageAll) {
        throw new AppError(
          "Bạn không có quyền truy cập tệp riêng tư này",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    return {
      ...file,
      url: file.isPublic
        ? this.r2Service.getPublicUrl(file.bucketKey)
        : undefined,
    };
  }

  async getPresignedDownloadUrl(
    id: string,
    userId?: string,
    permissions?: string[],
  ): Promise<DownloadUrlResponseDto> {
    const file = await this.repository.findById(id);
    if (!file) {
      throw new AppError("Tệp không tồn tại", 404, ERROR_CODE.FILE_NOT_FOUND);
    }

    if (!file.isConfirmed) {
      throw new AppError(
        "Tệp chưa hoàn tất tải lên hoặc chưa được xác nhận",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    if (!file.isPublic) {
      if (!userId) {
        throw new AppError(
          "Vui lòng đăng nhập để tải tệp riêng tư này",
          401,
          ERROR_CODE.UNAUTHORIZED,
        );
      }

      const userPermissions = await this.resolveEffectivePermissions(
        userId,
        permissions,
      );
      const canManageAll = userPermissions.includes(PERMISSIONS.FILE_MANAGE);
      const isOwner = file.userId === userId;

      if (!isOwner && !canManageAll) {
        throw new AppError(
          "Bạn không có quyền tải tệp riêng tư này",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    const expiresIn = 3600;

    const downloadUrl = await this.r2Service.getPresignedDownloadUrl(
      file.bucketKey,
      expiresIn,
      file.originalName,
    );

    return {
      downloadUrl,
      expiresIn,
      fileName: file.originalName,
    };
  }

  async listFiles(
    query: FileQueryDto,
    userId?: string,
    permissions?: string[],
  ) {
    const userPermissions = await this.resolveEffectivePermissions(
      userId,
      permissions,
    );
    const canManageAll = userPermissions.includes(PERMISSIONS.FILE_MANAGE);

    const result =
      query.search?.trim() && typeof this.repository.searchFts === "function"
        ? await this.repository.searchFts(query, userId, canManageAll)
        : await this.repository.findAll(query, userId, canManageAll);

    const mappedData = result.data.map((file) => ({
      ...file,
      url: file.isPublic
        ? this.r2Service.getPublicUrl(file.bucketKey)
        : undefined,
    }));

    return {
      data: mappedData,
      meta: result.meta,
    };
  }

  async deleteFile(
    id: string,
    userId?: string,
    permissions?: string[],
    metadata?: { ipAddress?: string; userAgent?: string },
  ): Promise<void> {
    const file = await this.repository.findById(id);
    if (!file) {
      throw new AppError("Tệp không tồn tại", 404, ERROR_CODE.FILE_NOT_FOUND);
    }

    const userPermissions = await this.resolveEffectivePermissions(
      userId,
      permissions,
    );
    const canManageAll = userPermissions.includes(PERMISSIONS.FILE_MANAGE);
    const isOwner = (file.userId ?? null) === (userId ?? null);
    const hasDeletePermission = userPermissions.includes(
      PERMISSIONS.FILE_DELETE,
    );

    if (!canManageAll && (!isOwner || !hasDeletePermission)) {
      throw new AppError(
        "Bạn không có quyền xóa tệp này",
        403,
        ERROR_CODE.FORBIDDEN,
      );
    }

    // Xóa file khỏi R2 bucket
    await this.r2Service.deleteFile(file.bucketKey).catch((err) => {
      console.warn(
        `[FileService] Failed to delete file ${file.bucketKey} from R2:`,
        err.message,
      );
    });

    // Soft delete bản ghi trong database
    await this.repository.delete(id);

    await this.repository.createAuditLog({
      actorId: userId,
      action: AUDIT_ACTION.DELETE_FILE,
      targetType: AUDIT_TARGET_TYPE.FILE,
      targetId: id,
      details: { bucketKey: file.bucketKey, fileName: file.fileName },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });
  }

  /**
   * Tải ảnh lên và tối ưu hóa nén / chuyển định dạng tự động bằng Sharp
   */
  async uploadAndProcessImage(
    file: {
      buffer: Buffer;
      originalname: string;
      mimetype: string;
      size: number;
    },
    options: DirectImageUploadDto = {},
    userId?: string,
    permissions?: string[],
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<FileResponseDto> {
    const effectivePerms = await this.resolveEffectivePermissions(
      userId,
      permissions,
    );
    const canUpload =
      effectivePerms.includes(PERMISSIONS.FILE_UPLOAD) ||
      effectivePerms.includes(PERMISSIONS.FILE_MANAGE);

    if (!canUpload) {
      throw new AppError(
        "Bạn không có quyền tải lên tệp tin",
        403,
        ERROR_CODE.FORBIDDEN,
      );
    }

    if (!file || !file.buffer || file.buffer.length === 0) {
      throw new AppError(
        "Vui lòng cung cấp tệp ảnh hợp lệ",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    // Xử lý nén & tối ưu ảnh qua Sharp
    const processed = await this.imageProcessor.processImage(file.buffer, {
      width: options.width,
      height: options.height,
      fit: options.fit,
      format: options.format || IMAGE_FORMAT.WEBP,
      quality: options.quality || MEDIA_LIMITS.DEFAULT_QUALITY,
    });

    const folder = options.folder || MEDIA_FOLDER.IMAGES;
    const ext = `.${processed.info.format}`;
    const cleanBasename = path
      .basename(file.originalname, path.extname(file.originalname))
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "-")
      .slice(0, 50);
    const finalFileName = `${cleanBasename || "image"}_${uuidv7().replace(/-/g, "").slice(0, 16)}${ext}`;
    const bucketKey = `${folder}/${userId || "public"}/${finalFileName}`;

    // Upload buffer đã nén lên R2
    await this.r2Service.uploadBuffer(
      bucketKey,
      processed.buffer,
      processed.info.mimeType,
    );

    const compressionRatio =
      file.size > 0
        ? `${Math.max(0, Math.round((1 - processed.info.size / file.size) * 100))}%`
        : "0%";

    let record;
    try {
      record = await this.repository.createDirectFile({
        userId: userId || null,
        originalName: file.originalname,
        fileName: finalFileName,
        mimeType: processed.info.mimeType,
        size: processed.info.size,
        bucketKey,
        folder,
        isPublic: options.isPublic ?? true,
        metadata: {
          width: processed.info.width,
          height: processed.info.height,
          format: processed.info.format,
          originalSize: file.size,
          compressedSize: processed.info.size,
          compressionRatio,
        },
      });
    } catch (dbErr) {
      await this.r2Service.deleteFiles([bucketKey]).catch(() => {});
      throw dbErr;
    }

    await this.repository.createAuditLog({
      actorId: userId,
      action: AUDIT_ACTION.UPLOAD_FILE,
      targetType: AUDIT_TARGET_TYPE.FILE,
      targetId: record.id,
      details: {
        bucketKey,
        originalSize: file.size,
        compressedSize: processed.info.size,
        compressionRatio,
        format: processed.info.format,
      },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return {
      ...record,
      url: record.isPublic
        ? this.r2Service.getPublicUrl(record.bucketKey)
        : undefined,
    };
  }

  /**
   * Biến đổi ảnh hiện có trong hệ thống qua Sharp (resize, crop, convert format)
   */
  async transformExistingImage(
    id: string,
    options: ImageTransformDto = {},
    userId?: string,
    permissions?: string[],
  ): Promise<
    | {
        buffer: Buffer;
        info: {
          format: string;
          width: number;
          height: number;
          size: number;
          mimeType: string;
        };
        isPublic?: boolean;
      }
    | FileResponseDto
  > {
    const file = await this.repository.findById(id);
    if (!file) {
      throw new AppError("Không tìm thấy tệp tin", 404, ERROR_CODE.NOT_FOUND);
    }

    const effectivePerms = await this.resolveEffectivePermissions(
      userId,
      permissions,
    );
    const canManageAll = effectivePerms.includes(PERMISSIONS.FILE_MANAGE);
    const isOwner = Boolean(file.userId && userId && file.userId === userId);

    if (!file.isPublic && !isOwner && !canManageAll) {
      if (!userId) {
        throw new AppError(
          "Vui lòng đăng nhập để truy cập tệp tin",
          401,
          ERROR_CODE.UNAUTHORIZED,
        );
      }
      throw new AppError(
        "Bạn không có quyền truy cập tệp tin này",
        403,
        ERROR_CODE.FORBIDDEN,
      );
    }

    // 1. Fast-fail nếu tệp không phải hình ảnh được hỗ trợ
    if (!this.imageProcessor.isSupportedImageMime(file.mimeType)) {
      throw new AppError(
        "Tệp tin không phải là hình ảnh được hỗ trợ chuyển đổi hoặc biến đổi",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    // 2. Tải buffer ảnh gốc từ R2 an toàn
    let originalBuffer: Buffer;
    try {
      originalBuffer = await this.r2Service.getObjectBuffer(file.bucketKey);
    } catch {
      throw new AppError(
        "Không tìm thấy dữ liệu tệp tin trên hệ thống lưu trữ",
        404,
        ERROR_CODE.NOT_FOUND,
      );
    }

    // 3. Biến đổi ảnh qua Sharp
    const processed = await this.imageProcessor.processImage(originalBuffer, {
      width: options.width,
      height: options.height,
      fit: options.fit,
      format: options.format,
      quality: options.quality,
    });

    // 4. Nếu người dùng yêu cầu lưu thành tệp mới (Bắt buộc xác thực và có quyền upload)
    if (options.saveAsNew) {
      if (!userId) {
        throw new AppError(
          "Vui lòng đăng nhập để lưu biến thể tệp tin mới",
          401,
          ERROR_CODE.UNAUTHORIZED,
        );
      }

      const canUpload =
        effectivePerms.includes(PERMISSIONS.FILE_UPLOAD) ||
        effectivePerms.includes(PERMISSIONS.FILE_MANAGE);
      if (!canUpload) {
        throw new AppError(
          "Bạn không có quyền lưu tệp tin mới",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }

      const ext = `.${processed.info.format}`;
      const newFileName = `transformed_${uuidv7().slice(0, 8)}${ext}`;
      const newBucketKey = `${file.folder}/${userId}/${newFileName}`;

      await this.r2Service.uploadBuffer(
        newBucketKey,
        processed.buffer,
        processed.info.mimeType,
      );

      let record;
      try {
        record = await this.repository.createDirectFile({
          userId,
          originalName: `transformed_${file.originalName}`,
          fileName: newFileName,
          mimeType: processed.info.mimeType,
          size: processed.info.size,
          bucketKey: newBucketKey,
          folder: file.folder,
          isPublic: file.isPublic,
          metadata: {
            sourceFileId: file.id,
            width: processed.info.width,
            height: processed.info.height,
            format: processed.info.format,
          },
        });
      } catch (dbErr) {
        await this.r2Service.deleteFiles([newBucketKey]).catch(() => {});
        throw dbErr;
      }

      return {
        ...record,
        url: record.isPublic
          ? this.r2Service.getPublicUrl(record.bucketKey)
          : undefined,
      };
    }

    return {
      ...processed,
      isPublic: file.isPublic,
    };
  }

  /**
   * Quét và dọn dẹp các tệp mồ côi (unconfirmed quá hạn và soft-deleted quá hạn retention)
   */
  async cleanupOrphanFiles(
    unconfirmedMaxAgeHours = MEDIA_LIMITS.UNCONFIRMED_CLEANUP_HOURS,
    softDeletedRetentionDays = MEDIA_LIMITS.SOFT_DELETED_RETENTION_DAYS,
    actorContext?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ): Promise<CleanupResultDto> {
    const unconfirmedCutoff = new Date(
      Date.now() - unconfirmedMaxAgeHours * 60 * 60 * 1000,
    );
    const softDeletedCutoff = new Date(
      Date.now() - softDeletedRetentionDays * 24 * 60 * 60 * 1000,
    );

    // 1. Dọn dẹp unconfirmed files
    const unconfirmed =
      await this.repository.findUnconfirmedOlderThan(unconfirmedCutoff);
    let unconfirmedCleaned = 0;
    if (unconfirmed.length > 0) {
      const keys = unconfirmed.map((f) => f.bucketKey);
      const ids = unconfirmed.map((f) => f.id);
      let r2Success = true;
      try {
        await this.r2Service.deleteFiles(keys);
      } catch (err: any) {
        r2Success = false;
        console.warn(
          "[FileService] Failed to delete unconfirmed files from R2:",
          err?.message || err,
        );
      }
      if (r2Success) {
        const res = await this.repository.hardDeleteMany(ids);
        unconfirmedCleaned = res.count;
      }
    }

    // 2. Dọn dẹp soft-deleted files past retention
    const softDeleted =
      await this.repository.findSoftDeletedOlderThan(softDeletedCutoff);
    let softDeletedCleaned = 0;
    if (softDeleted.length > 0) {
      const keys = softDeleted.map((f) => f.bucketKey);
      const ids = softDeleted.map((f) => f.id);
      let r2Success = true;
      try {
        await this.r2Service.deleteFiles(keys);
      } catch (err: any) {
        r2Success = false;
        console.warn(
          "[FileService] Failed to delete soft-deleted files from R2:",
          err?.message || err,
        );
      }
      if (r2Success) {
        const res = await this.repository.hardDeleteMany(ids);
        softDeletedCleaned = res.count;
      }
    }

    await this.repository.createAuditLog({
      actorId: actorContext?.actorId,
      action: AUDIT_ACTION.CLEANUP_ORPHAN_FILES,
      targetType: AUDIT_TARGET_TYPE.SYSTEM_CONFIG,
      targetId: SYSTEM_TARGET_ID,
      details: {
        unconfirmedCleaned,
        softDeletedCleaned,
        unconfirmedMaxAgeHours,
        softDeletedRetentionDays,
      },
      ipAddress: actorContext?.ipAddress,
      userAgent: actorContext?.userAgent,
    });

    return {
      unconfirmedCleaned,
      softDeletedCleaned,
      cleanedAt: new Date().toISOString(),
    };
  }
}

export const fileService = new FileService();
