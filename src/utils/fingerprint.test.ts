import { generateFingerprint, generateId } from "./fingerprint.js";

describe("generateFingerprint", () => {
  it("returns a 64-char hex SHA-256 hash", () => {
    const fp = generateFingerprint("npm-audit", "dependency", "package.json", "CVE-2024-1234");
    expect(fp).toMatch(/^[a-f0-9]{64}$/);
  });

  it("produces deterministic output for same inputs", () => {
    const a = generateFingerprint("tool", "cat", "path", "title");
    const b = generateFingerprint("tool", "cat", "path", "title");
    expect(a).toBe(b);
  });

  it("produces different output for different inputs", () => {
    const a = generateFingerprint("tool", "cat", "path", "title-a");
    const b = generateFingerprint("tool", "cat", "path", "title-b");
    expect(a).not.toBe(b);
  });

  it("normalizes case and whitespace", () => {
    const a = generateFingerprint("TOOL", "CAT", "PATH");
    const b = generateFingerprint("tool", "cat", "path");
    expect(a).toBe(b);
  });
});

describe("generateId", () => {
  it("returns the first 12 characters of the fingerprint", () => {
    const fp = generateFingerprint("a", "b", "c");
    const id = generateId(fp);
    expect(id).toBe(fp.slice(0, 12));
    expect(id).toHaveLength(12);
  });
});
