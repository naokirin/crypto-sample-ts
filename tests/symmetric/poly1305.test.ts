import { describe, expect, it } from "vitest";
import {
  POLY1305_KEY_LENGTH,
  POLY1305_TAG_LENGTH,
  computePoly1305MAC,
  generatePoly1305Key,
  verifyPoly1305MAC,
} from "../../src/symmetric/poly1305.js";

describe("Poly1305", () => {
  it("should compute and verify MAC correctly", () => {
    const key = generatePoly1305Key();
    const message = new TextEncoder().encode("Hello, World!");

    const tag = computePoly1305MAC(message, key);
    expect(tag).toBeDefined();
    expect(tag.length).toBe(POLY1305_TAG_LENGTH);

    const isValid = verifyPoly1305MAC(message, key, tag);
    expect(isValid).toBe(true);
  });

  it("should generate a key of correct length", () => {
    const key = generatePoly1305Key();
    expect(key.length).toBe(POLY1305_KEY_LENGTH);
  });

  it("should throw error for invalid key length", () => {
    const invalidKey = new Uint8Array(16); // 16バイト（32バイトが必要）
    const message = new TextEncoder().encode("test");

    expect(() => computePoly1305MAC(message, invalidKey)).toThrow("Invalid key length");
  });

  it("should throw error for invalid tag length", () => {
    const key = generatePoly1305Key();
    const message = new TextEncoder().encode("test");
    const invalidTag = new Uint8Array(8); // 8バイト（16バイトが必要）

    expect(() => verifyPoly1305MAC(message, key, invalidTag)).toThrow("Invalid tag length");
  });

  it("should return false when MAC verification fails", () => {
    const key = generatePoly1305Key();
    const message = new TextEncoder().encode("test");

    const tag = computePoly1305MAC(message, key);
    // タグを改ざん
    const tamperedTag = new Uint8Array(tag);
    tamperedTag[0] ^= 1;

    const isValid = verifyPoly1305MAC(message, key, tamperedTag);
    expect(isValid).toBe(false);
  });

  it("should return false when message is tampered", () => {
    const key = generatePoly1305Key();
    const message = new TextEncoder().encode("test");

    const tag = computePoly1305MAC(message, key);
    // メッセージを改ざん
    const tamperedMessage = new TextEncoder().encode("test!");

    const isValid = verifyPoly1305MAC(tamperedMessage, key, tag);
    expect(isValid).toBe(false);
  });

  it("should work with different message sizes", () => {
    const key = generatePoly1305Key();
    const messages = [
      new TextEncoder().encode(""),
      new TextEncoder().encode("a"),
      new TextEncoder().encode("Hello, World!"),
      new Uint8Array(1000).fill(42),
    ];

    for (const message of messages) {
      const tag = computePoly1305MAC(message, key);
      const isValid = verifyPoly1305MAC(message, key, tag);
      expect(isValid).toBe(true);
    }
  });

  it("should produce different tags for different keys", () => {
    const message = new TextEncoder().encode("test");
    const key1 = generatePoly1305Key();
    const key2 = generatePoly1305Key();

    const tag1 = computePoly1305MAC(message, key1);
    const tag2 = computePoly1305MAC(message, key2);

    expect(tag1).not.toEqual(tag2);
  });

  it("should produce different tags for different messages", () => {
    const key = generatePoly1305Key();
    const message1 = new TextEncoder().encode("test1");
    const message2 = new TextEncoder().encode("test2");

    const tag1 = computePoly1305MAC(message1, key);
    const tag2 = computePoly1305MAC(message2, key);

    expect(tag1).not.toEqual(tag2);
  });
});
