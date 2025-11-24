import { describe, expect, it } from "vitest";
import {
  CHACHA20_KEY_LENGTH,
  CHACHA20_NONCE_LENGTH,
  POLY1305_TAG_LENGTH,
  decryptChaCha20,
  encryptChaCha20,
  generateChaCha20Key,
} from "../../src/symmetric/chacha20.js";

describe("ChaCha20", () => {
  it("should encrypt and decrypt data correctly", () => {
    const key = generateChaCha20Key();
    const plaintext = new TextEncoder().encode("Hello, World!");

    const result = encryptChaCha20(plaintext, key);
    expect(result.ciphertext).toBeDefined();
    expect(result.authTag).toBeDefined();
    expect(result.nonce).toBeDefined();
    expect(result.nonce.length).toBe(CHACHA20_NONCE_LENGTH);
    expect(result.authTag.length).toBe(POLY1305_TAG_LENGTH);

    const decrypted = decryptChaCha20(result.ciphertext, key, result.nonce, result.authTag);
    expect(new TextDecoder().decode(decrypted)).toBe("Hello, World!");
  });

  it("should generate a key of correct length", () => {
    const key = generateChaCha20Key();
    expect(key.length).toBe(CHACHA20_KEY_LENGTH / 8);
  });

  it("should throw error for invalid key length", () => {
    const invalidKey = new Uint8Array(16); // 128ビット（256ビットが必要）
    const plaintext = new TextEncoder().encode("test");

    expect(() => encryptChaCha20(plaintext, invalidKey)).toThrow("Invalid key length");
  });

  it("should throw error for invalid nonce length", () => {
    const key = generateChaCha20Key();
    const plaintext = new TextEncoder().encode("test");
    const invalidNonce = new Uint8Array(12); // 12バイト（24バイトが必要）

    expect(() => encryptChaCha20(plaintext, key, invalidNonce)).toThrow("Invalid nonce length");
  });

  it("should throw error when authentication fails", () => {
    const key = generateChaCha20Key();
    const plaintext = new TextEncoder().encode("test");

    const result = encryptChaCha20(plaintext, key);
    // 認証タグを改ざん
    const tamperedTag = new Uint8Array(result.authTag);
    tamperedTag[0] ^= 1;

    expect(() => decryptChaCha20(result.ciphertext, key, result.nonce, tamperedTag)).toThrow(
      "Authentication failed"
    );
  });

  it("should work with different plaintext sizes", () => {
    const key = generateChaCha20Key();
    const plaintexts = [
      new TextEncoder().encode(""),
      new TextEncoder().encode("a"),
      new TextEncoder().encode("Hello, World!"),
      new Uint8Array(1000).fill(42),
    ];

    for (const plaintext of plaintexts) {
      const result = encryptChaCha20(plaintext, key);
      const decrypted = decryptChaCha20(result.ciphertext, key, result.nonce, result.authTag);
      expect(decrypted).toEqual(plaintext);
    }
  });
});
