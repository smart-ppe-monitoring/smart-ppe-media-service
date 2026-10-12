import { Request, Response, NextFunction } from "express";
import { FileService, fileService } from "./file.service";
import {
  RequestUploadUrlDto,
  ConfirmUploadDto,
  FileQueryDto,
  ImageTransformDto,
  DirectImageUploadDto,
} from "./file.dto";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";

export class FileController {
  constructor(private readonly service: FileService = fileService) {}

  requestUploadUrl = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const body = req.body as RequestUploadUrlDto;
      const result = await this.service.requestUploadUrl(
        body,
        req.user?.id,
        req.user?.permissions,
        {
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"],
        },
      );

      res.status(201).json({
        success: true,
        message: "Tạo link tải lên thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  confirmUpload = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as ConfirmUploadDto;
      const result = await this.service.confirmUpload(
        req.params.id,
        body,
        req.user?.id,
        req.user?.permissions,
        { ipAddress: req.ip, userAgent: req.headers["user-agent"] },
      );

      res.json({
        success: true,
        message: "Xác nhận tải tệp thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  findById = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.getFileById(
        req.params.id,
        req.user?.id,
        req.user?.permissions,
      );

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  getDownloadUrl = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.getPresignedDownloadUrl(
        req.params.id,
        req.user?.id,
        req.user?.permissions,
      );

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  downloadDirect = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.getPresignedDownloadUrl(
        req.params.id,
        req.user?.id,
        req.user?.permissions,
      );

      res.redirect(302, result.downloadUrl);
    } catch (error) {
      next(error);
    }
  };

  findAll = async (
    req: Request<unknown, unknown, unknown, FileQueryDto>,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const query = req.query;
      const result = await this.service.listFiles(
        query,
        req.user?.id,
        req.user?.permissions,
      );

      res.json({
        success: true,
        ...result,
      });
    } catch (error) {
      next(error);
    }
  };

  delete = async (req: Request, res: Response, next: NextFunction) => {
    try {
      await this.service.deleteFile(
        req.params.id,
        req.user?.id,
        req.user?.permissions,
        { ipAddress: req.ip, userAgent: req.headers["user-agent"] },
      );

      res.json({
        success: true,
        message: "Xóa tệp thành công",
      });
    } catch (error) {
      next(error);
    }
  };

  uploadImage = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.file) {
        throw new AppError(
          "Vui lòng chọn tệp ảnh để tải lên (field 'image')",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }

      const body = req.body as DirectImageUploadDto;
      const result = await this.service.uploadAndProcessImage(
        {
          buffer: req.file.buffer,
          originalname: req.file.originalname,
          mimetype: req.file.mimetype,
          size: req.file.size,
        },
        body,
        req.user?.id,
        req.user?.permissions,
        { ipAddress: req.ip, userAgent: req.headers["user-agent"] },
      );

      res.status(201).json({
        success: true,
        message: "Tải lên và tối ưu hóa ảnh thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  transformImage = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const query = req.query as unknown as ImageTransformDto;
      const result = await this.service.transformExistingImage(
        req.params.id,
        query,
        req.user?.id,
        req.user?.permissions,
      );

      // Nếu trả về buffer binary trực tiếp
      if ("buffer" in result && Buffer.isBuffer(result.buffer)) {
        res.setHeader("Content-Type", result.info.mimeType);
        res.setHeader("Content-Length", result.info.size);
        res.setHeader(
          "Cache-Control",
          "public, max-age=86400, stale-while-revalidate=3600",
        );
        return res.send(result.buffer);
      }

      // Trả về bản ghi FileRecord mới
      res.json({
        success: true,
        message: "Biến đổi và lưu ảnh mới thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  cleanupOrphanFiles = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { unconfirmedMaxAgeHours, softDeletedRetentionDays } =
        req.body || {};
      const result = await this.service.cleanupOrphanFiles(
        unconfirmedMaxAgeHours,
        softDeletedRetentionDays,
        {
          actorId: req.user?.id,
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"],
        },
      );

      res.json({
        success: true,
        message: "Dọn dẹp tệp rác thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };
}
