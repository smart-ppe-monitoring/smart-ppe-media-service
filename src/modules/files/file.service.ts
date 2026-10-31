import path from "node:path";
import { uuidv7 } from "uuidv7";
import { Prisma } from "@prisma/client-media";
import { FileRepository, fileRepository } from "./file.repository";
import { R2Service } from "../../common/services/r2.service";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import { ROLES } from "../../common/constants/role.constant";
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
    role?: string,
  ): Promise<string[]> {
    // SEC-30: Đồng bộ quyền quản trị viên khi role là ADMIN dù permissions rỗng hoặc dùng wildcard
    if (role === ROLES.ADMIN || role === "ADMIN") {
      return [
        PERMISSIONS.FILE_READ,
        PERMISSIONS.FILE_UPLOAD,
        PERMISSIONS.FILE_MANAGE,
        PERMISSIONS.FILE_DELETE,
        ...(permissions || []),
      ];
    }
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
    const lowerMime = mimeType.toLowerCase().trim();

    // SEC-24: Chặn triệt để SVG và các định dạng XML vector có nguy cơ Stored XSS
    const cleanMime = lowerMime.split(";")[0].trim();
    if (
      cleanMime === "image/svg+xml" ||
      cleanMime === "image/svg" ||
      cleanMime === "text/xml-svg" ||
      cleanMime === "image/vnd.adobe.svg+xml" ||
      cleanMime.endsWith("+xml") ||
      cleanMime.includes("svg")
    ) {
      return false;
    }

    return allowedPatterns.some((pattern) => {
      const lowerPattern = pattern.toLowerCase().trim();
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
    role?: string,
  ): Promise<UploadUrlResponseDto> {
    // Kiểm tra quyền FILE_UPLOAD nếu là người dùng đã đăng nhập (SEC-30: hỗ trợ vai trò ADMIN)
    if (userId) {
      const userPermissions = await this.resolveEffectivePermissions(
        userId,
        permissions,
        role,
      );
      const canUpload =
        role === ROLES.ADMIN ||
        role === "ADMIN" ||
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

    // 2. Kiểm tra định dạng MIME type và phần mở rộng cho phép (SEC-24)
    const fileExt = path.extname(data.fileName).toLowerCase();
    if (fileExt === ".svg" || fileExt === ".svgz") {
      throw new AppError(
        "Tệp định dạng SVG không được phép tải lên hệ thống vì lý do bảo mật",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

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
    if (typeof this.eventBus?.publish === "function") {
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
    }

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
    role?: string,
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
      role,
    );
    const canManageAll =
      role === ROLES.ADMIN ||
      role === "ADMIN" ||
      userPermissions.includes(PERMISSIONS.FILE_MANAGE);
    // CRIT-01 Fix: File anonymous (userId === null) không được tự động match với caller; chỉ admin (FILE_MANAGE) mới có thể xác nhận
    const isOwner = Boolean(file.userId && userId && file.userId === userId);

    if (!isOwner && !canManageAll) {
      throw new AppError(
        "Bạn không có quyền xác nhận tệp này",
        403,
        ERROR_CODE.FORBIDDEN,
      );
    }

    // SEC-05: Xác thực sự tồn tại của tệp và lấy dung lượng thực tế từ Object Storage qua HeadObject
    const headInfo = await this.r2Service.headObject(file.bucketKey);
    if (!headInfo.exists) {
      throw new AppError(
        "Tệp tin chưa được tải lên hệ thống lưu trữ R2/S3",
        400,
        ERROR_CODE.NOT_FOUND,
      );
    }

    const actualSize = headInfo.size;
    const maxFileSizeMb = 100;
    const maxSizeBytes = maxFileSizeMb * 1024 * 1024;
    if (actualSize > maxSizeBytes) {
      throw new AppError(
        `Dung lượng tệp thực tế (${Math.round(actualSize / 1024 / 1024)}MB) vượt quá giới hạn cấu hình cho phép (${maxFileSizeMb}MB)`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    // Sử dụng kích thước thực tế từ HeadObject thay vì tin cậy dữ liệu client gửi lên
    const finalSize = actualSize > 0 ? actualSize : (data?.size ?? file.size);
    const updated = await this.repository.confirmUpload(id, finalSize);

    await this.repository.createAuditLog({
      actorId: userId,
      action: AUDIT_ACTION.CONFIRM_FILE_UPLOAD,
      targetType: AUDIT_TARGET_TYPE.FILE,
      targetId: id,
      details: {
        bucketKey: file.bucketKey,
        size: finalSize,
        reportedSize: data?.size,
      },
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
    role?: string,
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
        role,
      );
      const canManageAll =
        role === ROLES.ADMIN ||
        role === "ADMIN" ||
        userPermissions.includes(PERMISSIONS.FILE_MANAGE);
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
    role?: string,
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
        role,
      );
      const canManageAll =
        role === ROLES.ADMIN ||
        role === "ADMIN" ||
        userPermissions.includes(PERMISSIONS.FILE_MANAGE);
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
    role?: string,
  ) {
    const userPermissions = await this.resolveEffectivePermissions(
      userId,
      permissions,
      role,
    );
    const canManageAll =
      role === ROLES.ADMIN ||
      role === "ADMIN" ||
      userPermissions.includes(PERMISSIONS.FILE_MANAGE);

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
    role?: string,
  ): Promise<void> {
    const file = await this.repository.findById(id);
    if (!file) {
      throw new AppError("Tệp không tồn tại", 404, ERROR_CODE.FILE_NOT_FOUND);
    }

    const userPermissions = await this.resolveEffectivePermissions(
      userId,
      permissions,
      role,
    );
    const canManageAll =
      role === ROLES.ADMIN ||
      role === "ADMIN" ||
      userPermissions.includes(PERMISSIONS.FILE_MANAGE);
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

    // Event-Driven Backbone: Publish file.deleted event (SEC-40)
    if (typeof this.eventBus?.publish === "function") {
      await this.eventBus
        .publish(EVENT_NAMES.FILE_DELETED, {
          fileId: file.id,
          bucketKey: file.bucketKey,
          deletedAt: new Date().toISOString(),
          actorId: userId || null,
        })
        .catch((err) => {
          console.warn(
            "[FileService] Failed to publish file.deleted event:",
            err?.message || err,
          );
        });
    }
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
    role?: string,
  ): Promise<FileResponseDto> {
    const effectivePerms = await this.resolveEffectivePermissions(
      userId,
      permissions,
      role,
    );
    const canUpload =
      role === ROLES.ADMIN ||
      role === "ADMIN" ||
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

    // Event-Driven Backbone: Publish file.created event (SEC-39)
    if (typeof this.eventBus?.publish === "function") {
      await this.eventBus
        .publish(EVENT_NAMES.FILE_CREATED, {
          fileId: record.id,
          bucketKey: record.bucketKey,
          fileName: record.fileName,
          mimeType: record.mimeType,
          size: record.size,
          userId: record.userId,
          folder: record.folder,
          isPublic: record.isPublic,
          metadata: (record.metadata as any) ?? {},
        })
        .catch((err) => {
          console.warn(
            "[FileService] Failed to publish file.created event:",
            err?.message || err,
          );
        });
    }

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
    role?: string,
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

    // SEC-60: Chặn truy cập và biến đổi các tệp chưa hoàn tất upload hoặc chưa được xác nhận
    if (!file.isConfirmed) {
      throw new AppError(
        "Tệp tin chưa hoàn tất tải lên hoặc chưa được xác nhận",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    const effectivePerms = await this.resolveEffectivePermissions(
      userId,
      permissions,
      role,
    );
    const canManageAll =
      role === ROLES.ADMIN ||
      role === "ADMIN" ||
      effectivePerms.includes(PERMISSIONS.FILE_MANAGE);
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

    // 2. Tải buffer ảnh gốc từ R2 an toàn (SEC-38)
    let originalBuffer: Buffer;
    try {
      originalBuffer = await this.r2Service.getObjectBuffer(file.bucketKey);
    } catch (err: any) {
      if (err instanceof AppError) {
        throw err;
      }
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
        canManageAll ||
        role === ROLES.ADMIN ||
        role === "ADMIN" ||
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

      if (typeof this.repository?.createAuditLog === "function") {
        await this.repository
          .createAuditLog({
            actorId: userId,
            action: AUDIT_ACTION.UPLOAD_FILE,
            targetType: AUDIT_TARGET_TYPE.FILE,
            targetId: record.id,
            details: {
              bucketKey: newBucketKey,
              sourceFileId: file.id,
              size: processed.info.size,
              format: processed.info.format,
              transformed: true,
            },
          })
          .catch(() => {});
      }

      // SEC-59: Event-Driven Backbone - Publish file.created event and record transactional outbox
      if (typeof this.eventBus?.publish === "function") {
        await this.eventBus
          .publish(EVENT_NAMES.FILE_CREATED, {
            fileId: record.id,
            bucketKey: record.bucketKey,
            fileName: record.fileName,
            mimeType: record.mimeType,
            size: record.size,
            userId: record.userId,
            folder: record.folder,
            isPublic: record.isPublic,
            metadata: (record.metadata as any) ?? {},
          })
          .catch((err) => {
            console.warn(
              "[FileService] Failed to publish file.created event for transformed image:",
              err?.message || err,
            );
          });
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
    // SEC-29: Chặn tiêu hủy bằng chứng kiểm toán bằng cách bắt buộc softDeletedRetentionDays tối thiểu 30 ngày
    if (softDeletedRetentionDays < MEDIA_LIMITS.SOFT_DELETED_RETENTION_DAYS) {
      throw new AppError(
        `Thời gian lưu giữ tệp đã xóa mềm tối thiểu là ${MEDIA_LIMITS.SOFT_DELETED_RETENTION_DAYS} ngày để bảo vệ bằng chứng kiểm toán`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const unconfirmedCutoff = new Date(
      Date.now() - unconfirmedMaxAgeHours * 60 * 60 * 1000,
    );
    const softDeletedCutoff = new Date(
      Date.now() - softDeletedRetentionDays * 24 * 60 * 60 * 1000,
    );

    // 1. Dọn dẹp unconfirmed files: Phối hợp 2 pha (2-phase cleanup) chống mồ côi (SEC-41)
    const unconfirmed =
      await this.repository.findUnconfirmedOlderThan(unconfirmedCutoff);
    let unconfirmedCleaned = 0;
    if (unconfirmed.length > 0) {
      const keys = unconfirmed.map((f) => f.bucketKey);
      const ids = unconfirmed.map((f) => f.id);

      // Phase 1: Đánh dấu CLEANUP_PENDING (cô lập trạng thái trong CSDL trước khi xóa storage)
      await this.repository.markCleanupPending(ids);

      // Phase 2: Xóa blobs vật lý khỏi R2
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

      // Phase 3: Hoàn tất hard delete bản ghi trong CSDL sau khi R2 xóa thành công
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
