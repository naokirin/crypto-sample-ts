import { describe, expect, it } from "vitest";
import {
  RSA_KEY_SIZE_2048,
  RSA_KEY_SIZE_4096,
  decryptRSA,
  encryptRSA,
  generateRsaKeyPair,
  importPrivateKey,
  importPublicKey,
  signRSA,
  verifyRSA,
} from "../../src/asymmetric/rsa.js";

describe("RSA", () => {
  describe("generateRsaKeyPair", () => {
    it("should generate a 2048-bit key pair", () => {
      const keyPair = generateRsaKeyPair(RSA_KEY_SIZE_2048);
      expect(keyPair.publicKey).toContain("BEGIN PUBLIC KEY");
      expect(keyPair.privateKey).toContain("BEGIN RSA PRIVATE KEY");
    });

    it("should generate a 4096-bit key pair", () => {
      const keyPair = generateRsaKeyPair(RSA_KEY_SIZE_4096);
      expect(keyPair.publicKey).toContain("BEGIN PUBLIC KEY");
      expect(keyPair.privateKey).toContain("BEGIN RSA PRIVATE KEY");
    });

    it("should use 2048-bit as default key size", () => {
      const keyPair = generateRsaKeyPair();
      expect(keyPair.publicKey).toContain("BEGIN PUBLIC KEY");
      expect(keyPair.privateKey).toContain("BEGIN RSA PRIVATE KEY");
    });

    it("should throw error for invalid key size", () => {
      expect(() => generateRsaKeyPair(1024)).toThrow("Invalid key size");
      expect(() => generateRsaKeyPair(3072)).toThrow("Invalid key size");
    });
  });

  describe("encryptRSA and decryptRSA", () => {
    it("should encrypt and decrypt data correctly", () => {
      const keyPair = generateRsaKeyPair();
      const plaintext = new TextEncoder().encode("Hello, World!");

      const encrypted = encryptRSA(plaintext, keyPair.publicKey);
      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.ciphertext.length).toBeGreaterThan(0);

      const decrypted = decryptRSA(encrypted.ciphertext, keyPair.privateKey);
      expect(new TextDecoder().decode(decrypted)).toBe("Hello, World!");
    });

    it("should work with empty plaintext", () => {
      const keyPair = generateRsaKeyPair();
      const plaintext = new Uint8Array(0);

      const encrypted = encryptRSA(plaintext, keyPair.publicKey);
      const decrypted = decryptRSA(encrypted.ciphertext, keyPair.privateKey);
      expect(decrypted).toEqual(plaintext);
    });

    it("should work with different plaintext sizes", () => {
      const keyPair = generateRsaKeyPair();
      const plaintexts = [
        new TextEncoder().encode("a"),
        new TextEncoder().encode("Hello, World!"),
        new TextEncoder().encode(
          "This is a longer message for testing RSA encryption and decryption."
        ),
      ];

      for (const plaintext of plaintexts) {
        const encrypted = encryptRSA(plaintext, keyPair.publicKey);
        const decrypted = decryptRSA(encrypted.ciphertext, keyPair.privateKey);
        expect(decrypted).toEqual(plaintext);
      }
    });

    it("should throw error for invalid public key", () => {
      const plaintext = new TextEncoder().encode("test");
      const invalidKey = "invalid key";

      expect(() => encryptRSA(plaintext, invalidKey)).toThrow("RSA encryption failed");
    });

    it("should throw error for invalid private key", () => {
      const keyPair = generateRsaKeyPair();
      const plaintext = new TextEncoder().encode("test");
      const encrypted = encryptRSA(plaintext, keyPair.publicKey);
      const invalidKey = "invalid key";

      expect(() => decryptRSA(encrypted.ciphertext, invalidKey)).toThrow("RSA decryption failed");
    });

    it("should not decrypt with wrong key pair", () => {
      const keyPair1 = generateRsaKeyPair();
      const keyPair2 = generateRsaKeyPair();
      const plaintext = new TextEncoder().encode("test");

      const encrypted = encryptRSA(plaintext, keyPair1.publicKey);
      expect(() => decryptRSA(encrypted.ciphertext, keyPair2.privateKey)).toThrow(
        "RSA decryption failed"
      );
    });
  });

  describe("signRSA and verifyRSA", () => {
    it("should sign and verify data correctly", () => {
      const keyPair = generateRsaKeyPair();
      const message = new TextEncoder().encode("Hello, World!");

      const signature = signRSA(message, keyPair.privateKey);
      expect(signature.signature).toBeDefined();
      expect(signature.signature.length).toBeGreaterThan(0);

      const isValid = verifyRSA(message, signature.signature, keyPair.publicKey);
      expect(isValid).toBe(true);
    });

    it("should work with different hash algorithms", () => {
      const keyPair = generateRsaKeyPair();
      const message = new TextEncoder().encode("test message");

      const algorithms = ["SHA-256", "SHA-384", "SHA-512"];
      for (const algorithm of algorithms) {
        const signature = signRSA(message, keyPair.privateKey, algorithm);
        const isValid = verifyRSA(message, signature.signature, keyPair.publicKey, algorithm);
        expect(isValid).toBe(true);
      }
    });

    it("should return false for tampered message", () => {
      const keyPair = generateRsaKeyPair();
      const message = new TextEncoder().encode("Hello, World!");
      const tamperedMessage = new TextEncoder().encode("Hello, World?!");

      const signature = signRSA(message, keyPair.privateKey);
      const isValid = verifyRSA(tamperedMessage, signature.signature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });

    it("should return false for tampered signature", () => {
      const keyPair = generateRsaKeyPair();
      const message = new TextEncoder().encode("Hello, World!");

      const signature = signRSA(message, keyPair.privateKey);
      // 署名を改ざん
      const tamperedSignature = `${signature.signature.slice(0, -2)}00`;

      const isValid = verifyRSA(message, tamperedSignature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });

    it("should throw error for invalid private key", () => {
      const message = new TextEncoder().encode("test");
      const invalidKey = "invalid key";

      expect(() => signRSA(message, invalidKey)).toThrow("RSA signing failed");
    });

    it("should throw error for invalid public key", () => {
      const keyPair = generateRsaKeyPair();
      const message = new TextEncoder().encode("test");
      const signature = signRSA(message, keyPair.privateKey);
      const invalidKey = "invalid key";

      expect(() => verifyRSA(message, signature.signature, invalidKey)).toThrow(
        "RSA verification failed"
      );
    });

    it("should not verify with wrong key pair", () => {
      const keyPair1 = generateRsaKeyPair();
      const keyPair2 = generateRsaKeyPair();
      const message = new TextEncoder().encode("test");

      const signature = signRSA(message, keyPair1.privateKey);
      const isValid = verifyRSA(message, signature.signature, keyPair2.publicKey);
      expect(isValid).toBe(false);
    });
  });

  describe("importPublicKey and importPrivateKey", () => {
    it("should import public key correctly", () => {
      const keyPair = generateRsaKeyPair();
      const publicKey = importPublicKey(keyPair.publicKey);
      expect(publicKey).toBeDefined();
    });

    it("should import private key correctly", () => {
      const keyPair = generateRsaKeyPair();
      const privateKey = importPrivateKey(keyPair.privateKey);
      expect(privateKey).toBeDefined();
    });

    it("should throw error for invalid public key", () => {
      expect(() => importPublicKey("invalid key")).toThrow("Failed to import public key");
    });

    it("should throw error for invalid private key", () => {
      expect(() => importPrivateKey("invalid key")).toThrow("Failed to import private key");
    });
  });
});
