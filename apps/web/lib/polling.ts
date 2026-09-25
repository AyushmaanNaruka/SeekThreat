/**
 * Frontend Polling Manager for SeekThreat Scans
 *
 * Provides utilities and state machine for scan polling:
 * - Identifies active vs terminal scan states
 * - Stops polling when all scans reach terminal states (completed, failed, cancelled)
 * - Maximum polling guard preventing indefinite polling if backend stalls
 * - Clean timer cleanup without memory leaks or stale intervals
 */

export const TERMINAL_SCAN_STATUSES = new Set([
  "completed",
  "failed",
  "cancelled",
]);

export const ACTIVE_SCAN_STATUSES = new Set([
  "pending",
  "running",
]);

export function isScanActive(status: string): boolean {
  return ACTIVE_SCAN_STATUSES.has(status);
}

export function isScanTerminal(status: string): boolean {
  return TERMINAL_SCAN_STATUSES.has(status);
}

export function hasActiveScans(scans: Array<{ status: string }>): boolean {
  return scans.some((s) => isScanActive(s.status));
}

export interface PollingConfig {
  activeIntervalMs?: number; // Interval while scans are active
  maxAttempts?: number; // Maximum consecutive polling attempts guard
}

export const DEFAULT_POLLING_CONFIG: Required<PollingConfig> = {
  activeIntervalMs: 2000,
  maxAttempts: 150, // 5 minutes at 2000ms interval
};

export class PollingController {
  private intervalId: any = null;
  private attemptCount = 0;
  private maxAttempts: number;
  private intervalMs: number;
  private onPoll: () => void | Promise<void>;
  private onMaxAttemptsReached?: () => void;

  constructor(options: {
    intervalMs?: number;
    maxAttempts?: number;
    onPoll: () => void | Promise<void>;
    onMaxAttemptsReached?: () => void;
  }) {
    this.intervalMs = options.intervalMs ?? DEFAULT_POLLING_CONFIG.activeIntervalMs;
    this.maxAttempts = options.maxAttempts ?? DEFAULT_POLLING_CONFIG.maxAttempts;
    this.onPoll = options.onPoll;
    this.onMaxAttemptsReached = options.onMaxAttemptsReached;
  }

  public update(hasActive: boolean): void {
    if (!hasActive) {
      this.stop();
      this.attemptCount = 0;
      return;
    }

    if (this.attemptCount >= this.maxAttempts) {
      this.stop();
      this.onMaxAttemptsReached?.();
      return;
    }

    if (this.intervalId === null) {
      this.intervalId = setInterval(async () => {
        this.attemptCount += 1;
        try {
          await this.onPoll();
        } catch {
          // Keep silent on transient polling failures
        }
        if (this.attemptCount >= this.maxAttempts) {
          this.stop();
          this.onMaxAttemptsReached?.();
        }
      }, this.intervalMs);
    }
  }

  public stop(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  public reset(): void {
    this.stop();
    this.attemptCount = 0;
  }

  public getAttempts(): number {
    return this.attemptCount;
  }

  public isRunning(): boolean {
    return this.intervalId !== null;
  }
}
