import { describe, expect, it } from "vitest";
import { SHA256_OUTPUT_SIZE, hashSHA256 } from "../../src/hash/sha256.js";
import { bytesToHex } from "../../src/utils/format.js";

describe("SHA-256", () => {
  it("should hash empty string correctly (NIST test vector)", async () => {
    const input = new Uint8Array(0);
    const hash = await hashSHA256(input);

    expect(hash.length).toBe(SHA256_OUTPUT_SIZE / 8);
    expect(bytesToHex(hash)).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it('should hash "abc" correctly (NIST test vector)', async () => {
    const input = new TextEncoder().encode("abc");
    const hash = await hashSHA256(input);

    expect(bytesToHex(hash)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });

  it('should hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" correctly', async () => {
    const input = new TextEncoder().encode(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    );
    const hash = await hashSHA256(input);

    expect(bytesToHex(hash)).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
  });

  it("should hash long input correctly (1 million 'a')", async () => {
    // 1,000,000個の'a'を含む文字列（1MB）
    const input = new Uint8Array(1000000).fill(97); // 97 = 'a'
    const hash = await hashSHA256(input);

    expect(bytesToHex(hash)).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
  });

  it("should be deterministic", async () => {
    const input = new TextEncoder().encode("Hello, World!");

    const hash1 = await hashSHA256(input);
    const hash2 = await hashSHA256(input);

    expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
  });

  it("should produce different hashes for different inputs", async () => {
    const input1 = new TextEncoder().encode("Hello, World!");
    const input2 = new TextEncoder().encode("Hello, World");

    const hash1 = await hashSHA256(input1);
    const hash2 = await hashSHA256(input2);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it("should handle various input sizes", async () => {
    const sizes = [0, 1, 16, 55, 56, 63, 64, 65, 127, 128, 256, 1024];

    for (const size of sizes) {
      const input = new Uint8Array(size).fill(42);
      const hash = await hashSHA256(input);

      expect(hash.length).toBe(SHA256_OUTPUT_SIZE / 8);
    }
  });
});
