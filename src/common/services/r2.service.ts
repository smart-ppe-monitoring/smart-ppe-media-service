import {
  S3Client,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  PutObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  ListObjectsV2CommandOutput,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { r2Config } from "../../config/r2.config";

export class R2Service {
  private readonly client: S3Client;
  private readonly bucketName: string;

  constructor() {
    this.bucketName = r2Config.bucketName;
    this.client = new S3Client({
      region: "auto",
      endpoint: `https://${r2Config.accountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: r2Config.accessKeyId,
        secretAccessKey: r2Config.secretAccessKey,
      },
    });
  }

  /**
   * Tạo presigned PUT URL để client upload trực tiếp lên R2.
   * @param key     Đường dẫn file trong bucket (VD: avatars/userId/1234.webp)
   * @param contentType  MIME type của file (VD: image/webp)
   * @returns URL có thể dùng để PUT file trong thời gian `presignedUrlExpiresIn` giây
   */
  async getPresignedUploadUrl(
    key: string,
    contentType: string,
    expiresInSeconds: number = r2Config.presignedUrlExpiresIn,
  ): Promise<string> {
    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      ContentType: contentType,
    });

    return getSignedUrl(this.client, command, {
      expiresIn: expiresInSeconds,
    });
  }

  /**
   * Tạo presigned GET URL để client tải file private an toàn từ R2.
   * @param key Đường dẫn file trong bucket
   * @param expiresInSeconds Thời gian hết hạn của URL (mặc định 3600 giây = 1 giờ)
   * @param originalFilename Tên file gốc (nếu truyền, sẽ thiết lập header Content-Disposition)
   */
  async getPresignedDownloadUrl(
    key: string,
    expiresInSeconds: number = 3600,
    originalFilename?: string,
  ): Promise<string> {
    let responseContentDisposition: string | undefined = undefined;
    if (originalFilename) {
      const asciiFallback = originalFilename
        .replace(/[^\x20-\x7E]/g, "_")
        .replace(/["\\]/g, "");
      const utf8Encoded = encodeURIComponent(originalFilename);
      responseContentDisposition = `attachment; filename="${asciiFallback}"; filename*=UTF-8''${utf8Encoded}`;
    }

    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      ResponseContentDisposition: responseContentDisposition,
    });

    return getSignedUrl(this.client, command, {
      expiresIn: expiresInSeconds,
    });
  }

  /**
   * Lấy URL public truy cập file trên R2.
   * @param key Đường dẫn file trong bucket
   */
  getPublicUrl(key: string): string {
    const base = r2Config.publicBaseUrl.replace(/\/$/, "");
    return `${base}/${key}`;
  }

  /**
   * Liệt kê TẤT CẢ các đối tượng trong bucket theo tiền tố (Prefix).
   * Sử dụng vòng lặp ContinuationToken để xử lý bucket lớn hơn 1000 objects.
   */
  async listObjects(
    prefix?: string,
  ): Promise<Array<{ key: string; lastModified?: Date; size?: number }>> {
    try {
      const allObjects: Array<{
        key: string;
        lastModified?: Date;
        size?: number;
      }> = [];
      let continuationToken: string | undefined = undefined;

      do {
        const command: ListObjectsV2Command = new ListObjectsV2Command({
          Bucket: this.bucketName,
          Prefix: prefix,
          ContinuationToken: continuationToken,
        });

        const response: ListObjectsV2CommandOutput =
          await this.client.send(command);
        if (response.Contents) {
          for (const obj of response.Contents) {
            if (obj.Key && obj.Key.length > 0) {
              allObjects.push({
                key: obj.Key,
                lastModified: obj.LastModified,
                size: obj.Size,
              });
            }
          }
        }

        continuationToken = response.IsTruncated
          ? response.NextContinuationToken
          : undefined;
      } while (continuationToken);

      return allObjects;
    } catch (err: any) {
      console.warn(
        "[R2Service] listObjects failed or bucket not accessible:",
        err.message,
      );
      return [];
    }
  }

  /**
   * Xóa file khỏi R2.
   * @param key Đường dẫn file trong bucket
   */
  async deleteFile(key: string): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });
    await this.client.send(command);
  }

  /**
   * Xóa hàng loạt file khỏi R2 theo batch (tối đa 1000 files/lần gọi theo chuẩn S3).
   * @param keys Danh sách đường dẫn file trong bucket
   */
  async deleteFiles(keys: string[]): Promise<void> {
    if (!keys || keys.length === 0) return;
    const CHUNK_SIZE = 1000;
    for (let i = 0; i < keys.length; i += CHUNK_SIZE) {
      const chunk = keys.slice(i, i + CHUNK_SIZE);
      const command = new DeleteObjectsCommand({
        Bucket: this.bucketName,
        Delete: {
          Objects: chunk.map((key) => ({ Key: key })),
          Quiet: true,
        },
      });
      await this.client.send(command);
    }
  }

  /**
   * Tải trực tiếp Buffer lên R2/S3 (dùng cho buffer ảnh đã xử lý bởi Sharp).
   * @param key Đường dẫn file trong bucket
   * @param buffer Dữ liệu binary
   * @param contentType MIME type của file
   */
  async uploadBuffer(
    key: string,
    buffer: Buffer,
    contentType: string,
  ): Promise<{ key: string; size: number }> {
    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      Body: buffer,
      ContentType: contentType,
    });
    await this.client.send(command);
    return { key, size: buffer.length };
  }

  /**
   * Tải Buffer tệp từ R2/S3 về bộ nhớ (dùng để xử lý biến đổi ảnh hoặc kiểm tra).
   * @param key Đường dẫn file trong bucket
   */
  async getObjectBuffer(key: string): Promise<Buffer> {
    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });
    const response = await this.client.send(command);
    if (!response.Body) {
      throw new Error(`Object body is empty for key: ${key}`);
    }
    if (typeof (response.Body as any).transformToByteArray === "function") {
      const byteArray = await (response.Body as any).transformToByteArray();
      return Buffer.from(byteArray);
    }
    const chunks: Buffer[] = [];
    for await (const chunk of response.Body as any) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
}
