import { describe, expect, it } from "vitest";
import {
  AES_IV_LENGTH,
  AES_KEY_LENGTH,
  AES_TAG_LENGTH,
  decryptAES,
  encryptAES,
  generateAESKey,
} from "../../src/symmetric/aes.js";

describe("AES", () => {
  it("should encrypt and decrypt data correctly", () => {
    const key = generateAESKey();
    const plaintext = new TextEncoder().encode("Hello, World!");

    const result = encryptAES(plaintext, key);
    expect(result.ciphertext).toBeDefined();
    expect(result.authTag).toBeDefined();
    expect(result.iv).toBeDefined();
    expect(result.iv.length).toBe(AES_IV_LENGTH);
    expect(result.authTag.length).toBe(AES_TAG_LENGTH);

    const decrypted = decryptAES(result.ciphertext, key, result.iv, result.authTag);
    expect(new TextDecoder().decode(decrypted)).toBe("Hello, World!");
  });

  it("should generate a key of correct length", () => {
    const key = generateAESKey();
    expect(key.length).toBe(AES_KEY_LENGTH / 8);
  });

  it("should throw error for invalid key length", () => {
    const invalidKey = new Uint8Array(16); // 128ビット（256ビットが必要）
    const plaintext = new TextEncoder().encode("test");

    expect(() => encryptAES(plaintext, invalidKey)).toThrow("Invalid key length");
  });

  it("should throw error for invalid IV length", () => {
    const key = generateAESKey();
    const plaintext = new TextEncoder().encode("test");
    const invalidIV = new Uint8Array(8); // 8バイト（12バイトが必要）

    expect(() => encryptAES(plaintext, key, invalidIV)).toThrow("Invalid IV length");
  });

  it("should throw error when authentication fails", () => {
    const key = generateAESKey();
    const plaintext = new TextEncoder().encode("test");

    const result = encryptAES(plaintext, key);
    // 認証タグを改ざん
    const tamperedTag = new Uint8Array(result.authTag);
    tamperedTag[0] ^= 1;

    expect(() => decryptAES(result.ciphertext, key, result.iv, tamperedTag)).toThrow(
      "Authentication failed"
    );
  });

  it("should work with different plaintext sizes", () => {
    const key = generateAESKey();
    const plaintexts = [
      new TextEncoder().encode(""),
      new TextEncoder().encode("a"),
      new TextEncoder().encode("Hello, World!"),
      new Uint8Array(1000).fill(42),
    ];

    for (const plaintext of plaintexts) {
      const result = encryptAES(plaintext, key);
      const decrypted = decryptAES(result.ciphertext, key, result.iv, result.authTag);
      expect(decrypted).toEqual(plaintext);
    }
  });
});
