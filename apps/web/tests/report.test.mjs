import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  REPORT_FORMATS,
  isReportFormat,
  reportPath,
  reportFilename,
  filenameFromDisposition,
} from "../lib/report.ts";

describe("report helpers", () => {
  it("knows exactly the two server formats", () => {
    assert.deepEqual([...REPORT_FORMATS], ["md", "json"]);
    assert.equal(isReportFormat("md"), true);
    assert.equal(isReportFormat("json"), true);
    assert.equal(isReportFormat("pdf"), false);
    assert.equal(isReportFormat(undefined), false);
  });

  it("encodes the engagement id in the path", () => {
    assert.equal(reportPath("eng-lab-baseline", "md"), "/engagements/eng-lab-baseline/report?format=md");
    assert.equal(reportPath("a/b c", "json"), "/engagements/a%2Fb%20c/report?format=json");
  });

  it("mirrors the server's download filename", () => {
    // Same cases as apps/api/routers/reports.py:_filename.
    assert.equal(reportFilename("eng-lab-baseline", "md"), "seekthreat-report-eng-lab-baseline.md");
    assert.equal(reportFilename("eng/../x y", "json"), "seekthreat-report-eng_.._x_y.json");
    assert.equal(reportFilename("...", "md"), "seekthreat-report-engagement.md");
  });

  it("reads Content-Disposition filenames and refuses paths", () => {
    assert.equal(
      filenameFromDisposition('attachment; filename="seekthreat-report-eng.md"'),
      "seekthreat-report-eng.md"
    );
    assert.equal(filenameFromDisposition("attachment; filename=report.json"), "report.json");
    assert.equal(filenameFromDisposition('attachment; filename="../etc/passwd"'), null);
    assert.equal(filenameFromDisposition("attachment"), null);
    assert.equal(filenameFromDisposition(null), null);
  });
});
