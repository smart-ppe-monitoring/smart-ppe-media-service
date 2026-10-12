export interface RequestUploadUrlDto {
  fileName: string;
  mimeType: string;
  size?: number;
  folder?: string;
  isPublic?: boolean;
  metadata?: Record<string, unknown>;
}

export interface UploadUrlResponseDto {
  fileId: string;
  uploadUrl: string;
  bucketKey: string;
  isPublic: boolean;
  expiresIn: number;
}

export interface ConfirmUploadDto {
  size?: number;
}

export interface FileQueryDto {
  folder?: string;
  isPublic?: boolean;
  mimeType?: string;
  search?: string;
  userId?: string;
  sortBy?: "createdAt" | "fileName" | "size";
  order?: "asc" | "desc";
  page?: number;
  limit?: number;
}

export interface FileResponseDto {
  id: string;
  userId: string | null;
  originalName: string;
  fileName: string;
  mimeType: string;
  size: number;
  bucketKey: string;
  folder: string;
  isPublic: boolean;
  isConfirmed: boolean;
  url?: string;
  metadata?: unknown;
  createdAt: Date;
  updatedAt: Date;
  user?: {
    id: string;
    fullName: string | null;
  } | null;
}

export interface DownloadUrlResponseDto {
  downloadUrl: string;
  expiresIn: number;
  fileName: string;
}

export interface ImageTransformDto {
  width?: number;
  height?: number;
  fit?: "cover" | "contain" | "fill" | "inside" | "outside";
  format?: "webp" | "jpeg" | "png" | "avif";
  quality?: number;
  saveAsNew?: boolean;
}

export interface DirectImageUploadDto {
  folder?: string;
  isPublic?: boolean;
  width?: number;
  height?: number;
  fit?: "cover" | "contain" | "fill" | "inside" | "outside";
  format?: "webp" | "jpeg" | "png" | "avif";
  quality?: number;
}

export interface CleanupResultDto {
  unconfirmedCleaned: number;
  softDeletedCleaned: number;
  cleanedAt: string;
}
