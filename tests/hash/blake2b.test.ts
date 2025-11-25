import { describe, expect, it } from "vitest";
import { BLAKE2B_OUTPUT_SIZE, hashBLAKE2b } from "../../src/hash/blake2b.js";
import { bytesToHex } from "../../src/utils/format.js";

describe("BLAKE2b", () => {
  it("should hash empty string correctly (official test vector)", async () => {
    const input = new Uint8Array(0);
    const hash = await hashBLAKE2b(input);

    expect(hash.length).toBe(BLAKE2B_OUTPUT_SIZE / 8);
    expect(bytesToHex(hash)).toBe(
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    );
  });

  it('should hash "abc" correctly (official test vector)', async () => {
    const input = new TextEncoder().encode("abc");
    const hash = await hashBLAKE2b(input);

    expect(bytesToHex(hash)).toBe(
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    );
  });

  it("should hash longer string correctly", async () => {
    const input = new TextEncoder().encode("The quick brown fox jumps over the lazy dog");
    const hash = await hashBLAKE2b(input);

    expect(bytesToHex(hash)).toBe(
      "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"
    );
  });

  it("should be deterministic", async () => {
    const input = new TextEncoder().encode("Hello, World!");

    const hash1 = await hashBLAKE2b(input);
    const hash2 = await hashBLAKE2b(input);

    expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
  });

  it("should produce different hashes for different inputs", async () => {
    const input1 = new TextEncoder().encode("Hello, World!");
    const input2 = new TextEncoder().encode("Hello, World");

    const hash1 = await hashBLAKE2b(input1);
    const hash2 = await hashBLAKE2b(input2);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it("should handle various input sizes", async () => {
    const sizes = [0, 1, 16, 127, 128, 129, 255, 256, 1024];

    for (const size of sizes) {
      const input = new Uint8Array(size).fill(42);
      const hash = await hashBLAKE2b(input);

      expect(hash.length).toBe(BLAKE2B_OUTPUT_SIZE / 8);
    }
  });

  it("should produce 512-bit (64-byte) output", async () => {
    const input = new TextEncoder().encode("test");
    const hash = await hashBLAKE2b(input);

    expect(hash.length).toBe(64); // 512 bits = 64 bytes
  });
});
