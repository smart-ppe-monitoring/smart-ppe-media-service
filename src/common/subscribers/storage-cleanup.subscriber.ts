import { eventBus, EventBusService } from "../services/event-bus.service";
import { EVENT_NAMES } from "../constants/event.constant";
import {
  FileUploadedUnconfirmedPayload,
  UserSoftDeletedPayload,
  EventEnvelope,
} from "../types/event.type";
import { R2Service, r2Service as defaultR2Service } from "../services/r2.service";
import {
  FileRepository,
  fileRepository as defaultFileRepository,
} from "../../modules/files/file.repository";

export class StorageCleanupSubscriber {
  private readonly bus: EventBusService;
  private readonly r2Service: R2Service;
  private readonly fileRepository: FileRepository;
  private readonly trackedUnconfirmedFiles: Map<
    string,
    FileUploadedUnconfirmedPayload
  > = new Map();
  private readonly activeTimers: Set<NodeJS.Timeout> = new Set();

  constructor(
    bus?: EventBusService,
    r2ServiceInstance?: R2Service,
    fileRepositoryInstance?: FileRepository,
  ) {
    this.bus = bus || eventBus;
    this.r2Service = r2ServiceInstance || defaultR2Service;
    this.fileRepository = fileRepositoryInstance || defaultFileRepository;
  }

  public register(): void {
    // Consumer: file.uploaded_unconfirmed
    this.bus.subscribe(
      EVENT_NAMES.FILE_UPLOADED_UNCONFIRMED,
      async (envelope: EventEnvelope<FileUploadedUnconfirmedPayload>) => {
        const { fileId, key, bucket, expiresAt } = envelope.payload;
        try {
          this.trackedUnconfirmedFiles.set(fileId, envelope.payload);
          // Giới hạn bộ nhớ đệm
          if (this.trackedUnconfirmedFiles.size > 1000) {
            const firstKey = this.trackedUnconfirmedFiles.keys().next().value;
            if (firstKey) this.trackedUnconfirmedFiles.delete(firstKey);
          }

          console.log(
            `[StorageCleanupSubscriber] 📦 Tracked unconfirmed upload: fileId=${fileId}, key=${key}, bucket=${bucket}, expiresAt=${expiresAt}`,
          );

          // SEC-17: Lên lịch dọn dẹp vật lý trên R2 khi hết hạn URL mà tệp vẫn chưa được confirm
          const expiresAtMs = new Date(expiresAt).getTime();
          const delayMs = Math.max(0, expiresAtMs - Date.now());
          const safeDelay = Math.min(delayMs, 24 * 60 * 60 * 1000);
          const timer = setTimeout(async () => {
            this.activeTimers.delete(timer);
            await this.cleanupExpiredUnconfirmedFile(fileId);
          }, safeDelay);
          if (typeof timer.unref === "function") {
            timer.unref();
          }
          this.activeTimers.add(timer);
        } catch (err: any) {
          console.warn(
            `[StorageCleanupSubscriber] ⚠️ Failed to track unconfirmed upload:`,
            err?.message || err,
          );
        }
      },
    );

    // SEC-63: Subscribe to user.soft_deleted for GDPR Article 17 Right to Erasure compliance
    this.bus.subscribe(
      EVENT_NAMES.USER_SOFT_DELETED,
      async (envelope: EventEnvelope<UserSoftDeletedPayload>) => {
        const { userId } = envelope.payload;
        if (userId) {
          await this.purgeUserMedia(userId);
        }
      },
    );
  }

  /**
   * SEC-63: GDPR Article 17 Right to Erasure
   * Xóa toàn bộ file và blob R2 khi nhận sự kiện user.soft_deleted
   */
  public async purgeUserMedia(userId: string): Promise<number> {
    try {
      const files = await this.fileRepository.findByUserId(userId);
      if (!files || files.length === 0) return 0;

      const keys = files.map((f: { id: string; bucketKey: string }) => f.bucketKey).filter(Boolean);
      if (keys.length > 0 && typeof this.r2Service.deleteFiles === "function") {
        await this.r2Service.deleteFiles(keys).catch((err: any) => {
          console.warn(
            `[StorageCleanupSubscriber] Failed to purge R2 files for deleted user ${userId}:`,
            err?.message || err,
          );
        });
      }

      await this.fileRepository.deleteByUserId(userId);
      console.log(
        `[StorageCleanupSubscriber] 🗑️ Purged ${files.length} media files for deleted user ${userId}`,
      );
      return files.length;
    } catch (err: any) {
      console.error(
        `[StorageCleanupSubscriber] Failed to purge media for user ${userId}:`,
        err?.message || err,
      );
      return 0;
    }
  }

  /**
   * SEC-17: Kiểm tra và xóa vật lý đối tượng trên R2 nếu sau khi hết hạn tệp vẫn chưa được xác nhận trong CSDL.
   */
  public async cleanupExpiredUnconfirmedFile(fileId: string): Promise<boolean> {
    const payload = this.trackedUnconfirmedFiles.get(fileId);
    if (!payload) return false;

    try {
      const file = await this.fileRepository.findById(fileId).catch(() => null);
      if (!file || !file.isConfirmed) {
        // Xóa thực tế trên Cloudflare R2 / S3
        await this.r2Service.deleteFile(payload.key).catch((err: any) => {
          console.warn(
            `[StorageCleanupSubscriber] Failed to delete abandoned R2 object ${payload.key}:`,
            err?.message || err,
          );
        });

        if (file) {
          await this.fileRepository.hardDeleteMany([fileId]).catch(() => {});
        }
      }
      this.trackedUnconfirmedFiles.delete(fileId);
      return true;
    } catch (err: any) {
      console.warn(
        `[StorageCleanupSubscriber] Error during cleanup of unconfirmed file ${fileId}:`,
        err?.message || err,
      );
      return false;
    }
  }

  public getTrackedFiles(): FileUploadedUnconfirmedPayload[] {
    return Array.from(this.trackedUnconfirmedFiles.values());
  }

  public clear(): void {
    for (const timer of this.activeTimers) {
      clearTimeout(timer);
    }
    this.activeTimers.clear();
    this.trackedUnconfirmedFiles.clear();
  }
}

export const storageCleanupSubscriber = new StorageCleanupSubscriber();
