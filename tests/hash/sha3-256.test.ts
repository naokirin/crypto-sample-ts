import { describe, expect, it } from "vitest";
import { SHA3_256_OUTPUT_SIZE, hashSHA3_256 } from "../../src/hash/sha3-256.js";
import { bytesToHex } from "../../src/utils/format.js";

describe("SHA-3-256", () => {
  it("should hash empty string correctly (NIST test vector)", async () => {
    const input = new Uint8Array(0);
    const hash = await hashSHA3_256(input);

    expect(hash.length).toBe(SHA3_256_OUTPUT_SIZE / 8);
    expect(bytesToHex(hash)).toBe(
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
  });

  it('should hash "abc" correctly (NIST test vector)', async () => {
    const input = new TextEncoder().encode("abc");
    const hash = await hashSHA3_256(input);

    expect(bytesToHex(hash)).toBe(
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
  });

  it("should hash longer string correctly", async () => {
    const input = new TextEncoder().encode(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    );
    const hash = await hashSHA3_256(input);

    expect(bytesToHex(hash)).toBe(
      "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    );
  });

  it("should hash long string correctly", async () => {
    const input = new TextEncoder().encode(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    );
    const hash = await hashSHA3_256(input);

    expect(bytesToHex(hash)).toBe(
      "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
    );
  });

  it("should be deterministic", async () => {
    const input = new TextEncoder().encode("Hello, World!");

    const hash1 = await hashSHA3_256(input);
    const hash2 = await hashSHA3_256(input);

    expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
  });

  it("should produce different hashes for different inputs", async () => {
    const input1 = new TextEncoder().encode("Hello, World!");
    const input2 = new TextEncoder().encode("Hello, World");

    const hash1 = await hashSHA3_256(input1);
    const hash2 = await hashSHA3_256(input2);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it("should handle various input sizes", async () => {
    const sizes = [0, 1, 16, 135, 136, 137, 255, 256, 1024];

    for (const size of sizes) {
      const input = new Uint8Array(size).fill(42);
      const hash = await hashSHA3_256(input);

      expect(hash.length).toBe(SHA3_256_OUTPUT_SIZE / 8);
    }
  });

  // SHA-3とSHA-256は異なる出力を生成することを確認
  it("should produce different output than SHA-256 for same input", async () => {
    const { hashSHA256 } = await import("../../src/hash/sha256.js");
    const input = new TextEncoder().encode("abc");

    const sha256Hash = await hashSHA256(input);
    const sha3Hash = await hashSHA3_256(input);

    // 両方とも32バイトだが、内容は異なる
    expect(sha256Hash.length).toBe(sha3Hash.length);
    expect(bytesToHex(sha256Hash)).not.toBe(bytesToHex(sha3Hash));
  });
});
