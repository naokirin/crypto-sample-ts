import { describe, expect, it } from "vitest";
import { hashSHA512, SHA512_OUTPUT_SIZE } from "../../src/hash/sha512.js";
import { bytesToHex } from "../../src/utils/format.js";

describe("SHA-512", () => {
  it("should hash empty string correctly (NIST test vector)", async () => {
    const input = new Uint8Array(0);
    const hash = await hashSHA512(input);

    expect(hash.length).toBe(SHA512_OUTPUT_SIZE / 8);
    expect(bytesToHex(hash)).toBe(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
  });

  it('should hash "abc" correctly (NIST test vector)', async () => {
    const input = new TextEncoder().encode("abc");
    const hash = await hashSHA512(input);

    expect(bytesToHex(hash)).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
  });

  it('should hash "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" correctly', async () => {
    const input = new TextEncoder().encode(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    );
    const hash = await hashSHA512(input);

    expect(bytesToHex(hash)).toBe(
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    );
  });

  it("should hash long input correctly (1 million 'a')", async () => {
    const input = new Uint8Array(1000000).fill(97); // 97 = 'a'
    const hash = await hashSHA512(input);

    expect(bytesToHex(hash)).toBe(
      "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
  });

  it("should be deterministic", async () => {
    const input = new TextEncoder().encode("Hello, World!");

    const hash1 = await hashSHA512(input);
    const hash2 = await hashSHA512(input);

    expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
  });

  it("should produce different hashes for different inputs", async () => {
    const input1 = new TextEncoder().encode("Hello, World!");
    const input2 = new TextEncoder().encode("Hello, World");

    const hash1 = await hashSHA512(input1);
    const hash2 = await hashSHA512(input2);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it("should handle various input sizes", async () => {
    const sizes = [0, 1, 16, 111, 112, 127, 128, 129, 255, 256, 1024];

    for (const size of sizes) {
      const input = new Uint8Array(size).fill(42);
      const hash = await hashSHA512(input);

      expect(hash.length).toBe(SHA512_OUTPUT_SIZE / 8);
    }
  });
});
