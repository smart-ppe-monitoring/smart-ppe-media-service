import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Interface cấu trúc dữ liệu Trace Context xuyên suốt chuỗi Async Operations.
 */
export interface TraceContextData {
  traceId: string;
  correlationId: string;
  requestId?: string;
  actorId?: string;
  source?: string;
  startTime: number;
  tags?: Record<string, string | number | boolean>;
}

/**
 * AsyncLocalStorage instance duy nhất quản lý Trace Context trong Node.js runtime.
 */
export const traceStorage = new AsyncLocalStorage<TraceContextData>();

/**
 * Thực thi một hàm (hoặc promise) bên trong một Trace Context xác định.
 */
export function runWithTraceContext<T>(
  context: TraceContextData,
  fn: () => T,
): T {
  return traceStorage.run(context, fn);
}

/**
 * Lấy toàn bộ dữ liệu Trace Context hiện tại (nếu đang chạy trong một trace context).
 */
export function getTraceContext(): TraceContextData | undefined {
  return traceStorage.getStore();
}

/**
 * Lấy traceId hiện tại, hoặc undefined nếu không có trace context đang chạy.
 */
export function getTraceId(): string | undefined {
  return traceStorage.getStore()?.traceId;
}

/**
 * Lấy correlationId hiện tại, hoặc undefined nếu không có.
 */
export function getCorrelationId(): string | undefined {
  const store = traceStorage.getStore();
  return store?.correlationId || store?.traceId;
}

/**
 * Đặt một tag thuộc tính vào Trace Context hiện tại để quan sát/ghi nhận logs.
 */
export function setTraceTag(
  key: string,
  value: string | number | boolean,
): void {
  const store = traceStorage.getStore();
  if (store) {
    if (!store.tags) {
      store.tags = {};
    }
    store.tags[key] = value;
  }
}

/**
 * Lấy thời gian đã trôi qua kể từ khi trace context bắt đầu (tính theo milliseconds).
 */
export function getTraceDurationMs(): number | undefined {
  const store = traceStorage.getStore();
  if (!store?.startTime) return undefined;
  return Date.now() - store.startTime;
}
