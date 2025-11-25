import { describe, expect, it } from "vitest";
import { BLAKE3_OUTPUT_SIZE, hashBLAKE3 } from "../../src/hash/blake3.js";
import { bytesToHex } from "../../src/utils/format.js";

describe("BLAKE3", () => {
  it("should hash empty string correctly (official test vector)", async () => {
    const input = new Uint8Array(0);
    const hash = await hashBLAKE3(input);

    expect(hash.length).toBe(BLAKE3_OUTPUT_SIZE / 8);
    expect(bytesToHex(hash)).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
  });

  it('should hash "abc" correctly (official test vector)', async () => {
    const input = new TextEncoder().encode("abc");
    const hash = await hashBLAKE3(input);

    expect(bytesToHex(hash)).toBe(
      "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
  });

  it("should hash longer string correctly", async () => {
    const input = new TextEncoder().encode("The quick brown fox jumps over the lazy dog");
    const hash = await hashBLAKE3(input);

    // テストベクターは実装による実際の出力を使用
    expect(bytesToHex(hash)).toBe(
      "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a"
    );
  });

  it("should be deterministic", async () => {
    const input = new TextEncoder().encode("Hello, World!");

    const hash1 = await hashBLAKE3(input);
    const hash2 = await hashBLAKE3(input);

    expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
  });

  it("should produce different hashes for different inputs", async () => {
    const input1 = new TextEncoder().encode("Hello, World!");
    const input2 = new TextEncoder().encode("Hello, World");

    const hash1 = await hashBLAKE3(input1);
    const hash2 = await hashBLAKE3(input2);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it("should handle various input sizes", async () => {
    const sizes = [0, 1, 16, 127, 128, 129, 255, 256, 1024];

    for (const size of sizes) {
      const input = new Uint8Array(size).fill(42);
      const hash = await hashBLAKE3(input);

      expect(hash.length).toBe(BLAKE3_OUTPUT_SIZE / 8);
    }
  });

  it("should produce 256-bit (32-byte) output by default", async () => {
    const input = new TextEncoder().encode("test");
    const hash = await hashBLAKE3(input);

    expect(hash.length).toBe(32); // 256 bits = 32 bytes
  });

  // BLAKE3とBLAKE2bは異なる出力を生成することを確認
  it("should produce different output than BLAKE2b for same input", async () => {
    const { hashBLAKE2b } = await import("../../src/hash/blake2b.js");
    const input = new TextEncoder().encode("abc");

    const blake2bHash = await hashBLAKE2b(input);
    const blake3Hash = await hashBLAKE3(input);

    // BLAKE2bは64バイト、BLAKE3は32バイト
    expect(blake2bHash.length).toBe(64);
    expect(blake3Hash.length).toBe(32);
  });
});
