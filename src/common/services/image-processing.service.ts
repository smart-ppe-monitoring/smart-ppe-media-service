import sharp from "sharp";
import { AppError } from "../errors/app-error";
import { ERROR_CODE } from "../errors/error-code";
import {
  IMAGE_FORMAT,
  IMAGE_FIT,
  MEDIA_LIMITS,
  ImageFormat,
  ImageFit,
  SUPPORTED_IMAGE_MIME_TYPES,
} from "../constants/media.constant";

export interface ImageTransformOptions {
  width?: number;
  height?: number;
  fit?: ImageFit;
  format?: ImageFormat;
  quality?: number;
  withoutEnlargement?: boolean;
  rotate?: number;
}

export interface ImageProcessResult {
  buffer: Buffer;
  info: {
    format: string;
    width: number;
    height: number;
    size: number;
    mimeType: string;
  };
}

export interface ImageMetadata {
  format?: string;
  width?: number;
  height?: number;
  space?: string;
  channels?: number;
  size?: number;
  hasAlpha?: boolean;
}

export class ImageProcessingService {
  /**
   * Xác thực buffer có phải là tệp ảnh hợp lệ và không vượt quá giới hạn an toàn.
   * Chống decompression bomb bằng cách giới hạn pixel tối đa (limitInputPixels).
   */
  async validateImageBuffer(buffer: Buffer): Promise<{
    isValid: boolean;
    metadata: ImageMetadata;
  }> {
    if (!buffer || buffer.length === 0) {
      throw new AppError(
        "Dữ liệu ảnh rỗng hoặc không hợp lệ",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    if (buffer.length > MEDIA_LIMITS.MAX_FILE_SIZE_BYTES) {
      throw new AppError(
        `Kích thước tệp vượt quá giới hạn cho phép (${MEDIA_LIMITS.MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB)`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    try {
      const pipeline = sharp(buffer, {
        failOn: "error",
        limitInputPixels:
          MEDIA_LIMITS.MAX_DIMENSION * MEDIA_LIMITS.MAX_DIMENSION,
      });

      const metadata = await pipeline.metadata();

      if (!metadata.format || !metadata.width || !metadata.height) {
        throw new AppError(
          "Không thể nhận diện định dạng hoặc kích thước ảnh",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }

      if (
        metadata.width > MEDIA_LIMITS.MAX_DIMENSION ||
        metadata.height > MEDIA_LIMITS.MAX_DIMENSION
      ) {
        throw new AppError(
          `Kích thước ảnh vượt quá giới hạn tối đa ${MEDIA_LIMITS.MAX_DIMENSION}x${MEDIA_LIMITS.MAX_DIMENSION}px`,
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }

      return {
        isValid: true,
        metadata: {
          format: metadata.format,
          width: metadata.width,
          height: metadata.height,
          space: metadata.space,
          channels: metadata.channels,
          size: buffer.length,
          hasAlpha: metadata.hasAlpha,
        },
      };
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(
        "Tệp không phải là hình ảnh hợp lệ hoặc dữ liệu bị lỗi",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }
  }

  /**
   * Lấy thông tin metadata kỹ thuật của ảnh
   */
  async getImageMetadata(buffer: Buffer): Promise<ImageMetadata> {
    const { metadata } = await this.validateImageBuffer(buffer);
    return metadata;
  }

  /**
   * Xử lý biến đổi hình ảnh: resize, crop, convert format, nén chất lượng
   */
  async processImage(
    buffer: Buffer,
    options: ImageTransformOptions = {},
  ): Promise<ImageProcessResult> {
    await this.validateImageBuffer(buffer);

    const {
      width,
      height,
      fit = IMAGE_FIT.COVER,
      format = IMAGE_FORMAT.WEBP,
      quality = MEDIA_LIMITS.DEFAULT_QUALITY,
      withoutEnlargement = true,
      rotate,
    } = options;

    // Giới hạn chất lượng an toàn
    const clampedQuality = Math.max(
      MEDIA_LIMITS.MIN_QUALITY,
      Math.min(MEDIA_LIMITS.MAX_QUALITY, quality),
    );

    let pipeline = sharp(buffer, {
      failOn: "error",
      limitInputPixels: MEDIA_LIMITS.MAX_DIMENSION * MEDIA_LIMITS.MAX_DIMENSION,
    });

    // 1. Rotate nếu cần
    if (typeof rotate === "number") {
      pipeline = pipeline.rotate(rotate);
    } else {
      // Auto-orient theo EXIF
      pipeline = pipeline.rotate();
    }

    // 2. Resize nếu có kích thước
    if (width || height) {
      pipeline = pipeline.resize({
        width: width
          ? Math.max(
              MEDIA_LIMITS.MIN_DIMENSION,
              Math.min(MEDIA_LIMITS.MAX_DIMENSION, width),
            )
          : undefined,
        height: height
          ? Math.max(
              MEDIA_LIMITS.MIN_DIMENSION,
              Math.min(MEDIA_LIMITS.MAX_DIMENSION, height),
            )
          : undefined,
        fit,
        withoutEnlargement,
      });
    }

    // 3. Format & Quality Encoding
    let mimeType = "image/webp";
    switch (format) {
      case IMAGE_FORMAT.WEBP:
        pipeline = pipeline.webp({ quality: clampedQuality, effort: 4 });
        mimeType = "image/webp";
        break;
      case IMAGE_FORMAT.JPEG:
        pipeline = pipeline.jpeg({ quality: clampedQuality, mozjpeg: true });
        mimeType = "image/jpeg";
        break;
      case IMAGE_FORMAT.PNG:
        pipeline = pipeline.png({
          compressionLevel: 8,
          quality: clampedQuality,
        });
        mimeType = "image/png";
        break;
      case IMAGE_FORMAT.AVIF:
        pipeline = pipeline.avif({ quality: clampedQuality, effort: 4 });
        mimeType = "image/avif";
        break;
      default:
        pipeline = pipeline.webp({ quality: clampedQuality });
        mimeType = "image/webp";
        break;
    }

    const { data, info } = await pipeline.toBuffer({ resolveWithObject: true });

    return {
      buffer: data,
      info: {
        format: format || (info.format === "heif" ? "avif" : info.format),
        width: info.width,
        height: info.height,
        size: data.length,
        mimeType,
      },
    };
  }

  /**
   * Sinh avatar vuông chuẩn hóa WebP (256x256, chất lượng cao 80)
   */
  async generateAvatar(
    buffer: Buffer,
    size = MEDIA_LIMITS.DEFAULT_AVATAR_SIZE,
  ): Promise<ImageProcessResult> {
    return this.processImage(buffer, {
      width: size,
      height: size,
      fit: IMAGE_FIT.COVER,
      format: IMAGE_FORMAT.WEBP,
      quality: MEDIA_LIMITS.DEFAULT_QUALITY,
      withoutEnlargement: false,
    });
  }

  /**
   * Sinh ảnh thu nhỏ Thumbnail WebP (fit: inside)
   */
  async generateThumbnail(
    buffer: Buffer,
    width = MEDIA_LIMITS.DEFAULT_THUMBNAIL_WIDTH,
    height = MEDIA_LIMITS.DEFAULT_THUMBNAIL_HEIGHT,
  ): Promise<ImageProcessResult> {
    return this.processImage(buffer, {
      width,
      height,
      fit: IMAGE_FIT.INSIDE,
      format: IMAGE_FORMAT.WEBP,
      quality: 75,
      withoutEnlargement: true,
    });
  }

  /**
   * Kiểm tra MIME type ảnh có được hỗ trợ xử lý không
   */
  isSupportedImageMime(mimeType?: string | null): boolean {
    if (!mimeType) return false;
    return (SUPPORTED_IMAGE_MIME_TYPES as readonly string[]).includes(
      mimeType.toLowerCase(),
    );
  }
}

export const imageProcessingService = new ImageProcessingService();
