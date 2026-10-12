import { eventBus, EventBusService } from "../services/event-bus.service";
import { EVENT_NAMES } from "../constants/event.constant";
import {
  FileUploadedUnconfirmedPayload,
  EventEnvelope,
} from "../types/event.type";

export class StorageCleanupSubscriber {
  private readonly bus: EventBusService;
  private readonly trackedUnconfirmedFiles: Map<
    string,
    FileUploadedUnconfirmedPayload
  > = new Map();

  constructor(bus?: EventBusService) {
    this.bus = bus || eventBus;
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
        } catch (err: any) {
          console.warn(
            `[StorageCleanupSubscriber] ⚠️ Failed to track unconfirmed upload:`,
            err?.message || err,
          );
        }
      },
    );
  }

  public getTrackedFiles(): FileUploadedUnconfirmedPayload[] {
    return Array.from(this.trackedUnconfirmedFiles.values());
  }

  public clear(): void {
    this.trackedUnconfirmedFiles.clear();
  }
}

export const storageCleanupSubscriber = new StorageCleanupSubscriber();
