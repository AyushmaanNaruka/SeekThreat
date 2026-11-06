import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { scannerTitle } from "../lib/scanOptions.ts";

describe("scannerTitle", () => {
  it("labels every scanner distinctly", () => {
    assert.equal(scannerTitle("nmap"), "Nmap Network Scan");
    assert.equal(scannerTitle("nuclei"), "Nuclei Vulnerability Scan");
    assert.equal(scannerTitle("nikto"), "Nikto Web Server Scan");
    assert.equal(scannerTitle("ssh-audit"), "SSH Audit");
  });
});
