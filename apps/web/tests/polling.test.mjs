import test, { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import {
  isScanActive,
  isScanTerminal,
  hasActiveScans,
  TERMINAL_SCAN_STATUSES,
  ACTIVE_SCAN_STATUSES,
  DEFAULT_POLLING_CONFIG,
  PollingController,
} from "../lib/polling.ts";

describe("Issue #5: Frontend Scan Polling Lifecycle & Maximum Guard", () => {
  it("1. Polling occurs while a scan is pending", () => {
    const scans = [{ scan_id: "s-1", status: "pending" }];
    assert.equal(isScanActive("pending"), true);
    assert.equal(hasActiveScans(scans), true);

    let pollCount = 0;
    const controller = new PollingController({
      intervalMs: 50,
      maxAttempts: 10,
      onPoll: () => {
        pollCount += 1;
      },
    });

    controller.update(hasActiveScans(scans));
    assert.equal(controller.isRunning(), true);
    controller.stop();
  });

  it("2. Polling occurs while a scan is running", () => {
    const scans = [{ scan_id: "s-2", status: "running" }];
    assert.equal(isScanActive("running"), true);
    assert.equal(hasActiveScans(scans), true);

    let pollCount = 0;
    const controller = new PollingController({
      intervalMs: 50,
      maxAttempts: 10,
      onPoll: () => {
        pollCount += 1;
      },
    });

    controller.update(hasActiveScans(scans));
    assert.equal(controller.isRunning(), true);
    controller.stop();
  });

  it("3. Polling stops when the scan becomes completed", () => {
    assert.equal(isScanTerminal("completed"), true);
    assert.equal(isScanActive("completed"), false);

    const completedScans = [{ scan_id: "s-3", status: "completed" }];
    assert.equal(hasActiveScans(completedScans), false);

    const controller = new PollingController({
      intervalMs: 50,
      maxAttempts: 10,
      onPoll: () => {},
    });

    // Start with running scan
    controller.update(true);
    assert.equal(controller.isRunning(), true);

    // Transition to completed scan -> polling must stop
    controller.update(hasActiveScans(completedScans));
    assert.equal(controller.isRunning(), false);
    assert.equal(controller.getAttempts(), 0);
  });

  it("4. Polling stops when the scan becomes failed", () => {
    assert.equal(isScanTerminal("failed"), true);
    assert.equal(isScanActive("failed"), false);

    const failedScans = [{ scan_id: "s-4", status: "failed", error_message: "Process terminated abnormally" }];
    assert.equal(hasActiveScans(failedScans), false);

    const controller = new PollingController({
      intervalMs: 50,
      maxAttempts: 10,
      onPoll: () => {},
    });

    // Start with pending scan
    controller.update(true);
    assert.equal(controller.isRunning(), true);

    // Transition to failed scan -> polling must stop
    controller.update(hasActiveScans(failedScans));
    assert.equal(controller.isRunning(), false);
    assert.equal(controller.getAttempts(), 0);
  });

  it("5. Polling stops when the scan becomes cancelled", () => {
    assert.equal(isScanTerminal("cancelled"), true);
    assert.equal(isScanActive("cancelled"), false);

    const cancelledScans = [{ scan_id: "s-5", status: "cancelled" }];
    assert.equal(hasActiveScans(cancelledScans), false);

    const controller = new PollingController({
      intervalMs: 50,
      maxAttempts: 10,
      onPoll: () => {},
    });

    controller.update(true);
    assert.equal(controller.isRunning(), true);

    controller.update(hasActiveScans(cancelledScans));
    assert.equal(controller.isRunning(), false);
  });

  it("6. Maximum polling guard prevents indefinite polling when scan stays active", async () => {
    let guardExceeded = false;
    let pollCount = 0;

    let resolveGuardReached;
    const guardReachedPromise = new Promise((resolve) => {
      resolveGuardReached = resolve;
    });

    const controller = new PollingController({
      intervalMs: 15,
      maxAttempts: 5,
      onPoll: () => {
        pollCount += 1;
      },
      onMaxAttemptsReached: () => {
        guardExceeded = true;
        resolveGuardReached();
      },
    });

    // Start polling with an active scan
    controller.update(true);
    assert.equal(controller.isRunning(), true);

    // Wait for polling attempts to reach maxAttempts
    await guardReachedPromise;

    assert.equal(pollCount >= 5, true);
    assert.equal(guardExceeded, true);
    assert.equal(controller.isRunning(), false);
  });

  it("7. Timers and intervals are cleaned up correctly on stop/reset without leaks", () => {
    let pollCount = 0;
    const controller = new PollingController({
      intervalMs: 20,
      maxAttempts: 50,
      onPoll: () => {
        pollCount += 1;
      },
    });

    controller.update(true);
    assert.equal(controller.isRunning(), true);

    controller.stop();
    assert.equal(controller.isRunning(), false);

    const countAtStop = pollCount;
    // Verify no further polling occurs after stop
    return new Promise((resolve) => {
      setTimeout(() => {
        assert.equal(pollCount, countAtStop);
        resolve();
      }, 60);
    });
  });

  it("8. Failed scan error information structure is properly validated", () => {
    const failedScan = {
      scan_id: "scan-err-01",
      engagement_id: "eng-01",
      scanner: "nmap",
      target: "127.0.0.1",
      status: "failed",
      observation_count: 0,
      artifact_id: null,
      error_message: "RuntimeError: Scanner socket connection refused",
      created_at: "2026-09-22T10:00:00Z",
      completed_at: "2026-09-22T10:00:05Z",
    };

    assert.equal(failedScan.status, "failed");
    assert.equal(typeof failedScan.error_message, "string");
    assert.match(failedScan.error_message, /Scanner socket connection refused/);
    assert.equal(isScanTerminal(failedScan.status), true);
    assert.equal(hasActiveScans([failedScan]), false);
  });
});
