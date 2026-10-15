import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  splitHostPortScheme,
  buildNucleiRequest,
  buildNiktoRequest,
  buildSshAuditRequest,
  scannerTitle,
  NUCLEI_TEMPLATE,
} from "../lib/scanOptions.ts";

describe("splitHostPortScheme", () => {
  it("leaves a bare host alone", () => {
    assert.deepEqual(splitHostPortScheme("localhost"), { host: "localhost", scheme: "http", port: null });
  });
  it("splits host:port", () => {
    assert.deepEqual(splitHostPortScheme("172.20.1.10:8080"), { host: "172.20.1.10", scheme: "http", port: "8080" });
  });
  it("splits an https URL and never leaves a URL in host", () => {
    assert.deepEqual(splitHostPortScheme("https://lab.local:8443/path"), { host: "lab.local", scheme: "https", port: "8443" });
  });
  it("unbrackets an IPv6 literal from a URL", () => {
    assert.equal(splitHostPortScheme("http://[::1]:8080/").host, "::1");
  });
  it("keeps a bare IPv6 address whole, with no port", () => {
    assert.deepEqual(splitHostPortScheme("fd00::5"), { host: "fd00::5", scheme: "http", port: null });
    assert.deepEqual(splitHostPortScheme("::1"), { host: "::1", scheme: "http", port: null });
  });
  it("splits a bracketed IPv6 address with a port", () => {
    assert.deepEqual(splitHostPortScheme("[fd00::5]:2222"), { host: "fd00::5", scheme: "http", port: "2222" });
    assert.deepEqual(splitHostPortScheme("[::1]"), { host: "::1", scheme: "http", port: null });
  });
  it("passes an invalid port through for the API to reject, never silently drops it", () => {
    assert.equal(splitHostPortScheme("172.20.1.10:80a").port, "80a");
    assert.equal(buildSshAuditRequest("172.20.2.50:ssh").options.port, "ssh");
  });
});

describe("nuclei request (behaviour unchanged, D-025)", () => {
  it("sends bare host, scheme, port and the template", () => {
    assert.deepEqual(buildNucleiRequest("http://localhost:8080"), {
      target: "localhost",
      options: { template: NUCLEI_TEMPLATE, scheme: "http", port: "8080" },
    });
  });
  it("omits port when none given", () => {
    assert.deepEqual(buildNucleiRequest("localhost").options, { template: NUCLEI_TEMPLATE, scheme: "http" });
  });
});

describe("nikto request", () => {
  it("splits host:port and sends scheme, never a template", () => {
    assert.deepEqual(buildNiktoRequest("172.20.1.10:8080"), {
      target: "172.20.1.10",
      options: { port: "8080", scheme: "http" },
    });
  });
  it("defaults to port 80 for a bare host", () => {
    assert.deepEqual(buildNiktoRequest("172.20.1.10").options, { port: "80", scheme: "http" });
  });
  it("defaults to port 443 for an https URL without a port", () => {
    assert.deepEqual(buildNiktoRequest("https://lab.local"), {
      target: "lab.local",
      options: { port: "443", scheme: "https" },
    });
  });
  it("includes timeout only when valid", () => {
    assert.equal(buildNiktoRequest("h", 120).options.timeout, 120);
    assert.equal("timeout" in buildNiktoRequest("h", 0).options, false);
    assert.equal("timeout" in buildNiktoRequest("h").options, false);
    assert.equal("template" in buildNiktoRequest("h").options, false);
  });
});

describe("ssh-audit request", () => {
  it("splits host:port and sends no scheme", () => {
    assert.deepEqual(buildSshAuditRequest("172.20.2.50:2222"), {
      target: "172.20.2.50",
      options: { port: "2222" },
    });
  });
  it("defaults to port 22", () => {
    assert.deepEqual(buildSshAuditRequest("172.20.2.50").options, { port: "22" });
  });
  it("includes timeout when given", () => {
    assert.deepEqual(buildSshAuditRequest("h", 30).options, { port: "22", timeout: 30 });
  });
});

describe("scannerTitle", () => {
  it("labels every scanner distinctly", () => {
    assert.equal(scannerTitle("nmap"), "Nmap Network Scan");
    assert.equal(scannerTitle("nuclei"), "Nuclei Vulnerability Scan");
    assert.equal(scannerTitle("nikto"), "Nikto Web Server Scan");
    assert.equal(scannerTitle("ssh-audit"), "SSH Audit");
  });
});
