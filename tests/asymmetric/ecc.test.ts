import { describe, expect, it } from "vitest";
import {
  computeEcdh,
  generateEccKeyPair,
  signEcdsa,
  signEddsa,
  verifyEcdsa,
  verifyEddsa,
} from "../../src/asymmetric/ecc.js";

describe("ECC", () => {
  describe("generateEccKeyPair", () => {
    it("should generate a secp256k1 key pair", () => {
      const keyPair = generateEccKeyPair("secp256k1");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.curve).toBe("secp256k1");
      expect(keyPair.privateKey.length).toBeGreaterThan(0);
      expect(keyPair.publicKey.length).toBeGreaterThan(0);
    });

    it("should generate a p256 key pair", () => {
      const keyPair = generateEccKeyPair("p256");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.curve).toBe("p256");
    });

    it("should generate a p384 key pair", () => {
      const keyPair = generateEccKeyPair("p384");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.curve).toBe("p384");
    });

    it("should generate a p521 key pair", () => {
      const keyPair = generateEccKeyPair("p521");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.curve).toBe("p521");
    });

    it("should generate an ed25519 key pair", () => {
      const keyPair = generateEccKeyPair("ed25519");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.curve).toBe("ed25519");
    });

    it("should generate an ed448 key pair", () => {
      const keyPair = generateEccKeyPair("ed448");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.curve).toBe("ed448");
    });

    it("should use secp256k1 as default curve", () => {
      const keyPair = generateEccKeyPair();
      expect(keyPair.curve).toBe("secp256k1");
    });
  });

  describe("signEcdsa and verifyEcdsa", () => {
    it("should sign and verify data correctly with secp256k1", () => {
      const keyPair = generateEccKeyPair("secp256k1");
      const message = new TextEncoder().encode("Hello, World!");

      const signature = signEcdsa(message, keyPair.privateKey, "secp256k1");
      expect(signature.signature).toBeDefined();
      expect(signature.signature.length).toBeGreaterThan(0);

      const isValid = verifyEcdsa(message, signature.signature, keyPair.publicKey, "secp256k1");
      expect(isValid).toBe(true);
    });

    it("should sign and verify data correctly with p256", () => {
      const keyPair = generateEccKeyPair("p256");
      const message = new TextEncoder().encode("Hello, World!");

      const signature = signEcdsa(message, keyPair.privateKey, "p256");
      const isValid = verifyEcdsa(message, signature.signature, keyPair.publicKey, "p256");
      expect(isValid).toBe(true);
    });

    it("should return false for tampered message", () => {
      const keyPair = generateEccKeyPair("secp256k1");
      const message = new TextEncoder().encode("Hello, World!");
      const tamperedMessage = new TextEncoder().encode("Hello, World?!");

      const signature = signEcdsa(message, keyPair.privateKey, "secp256k1");
      const isValid = verifyEcdsa(
        tamperedMessage,
        signature.signature,
        keyPair.publicKey,
        "secp256k1"
      );
      expect(isValid).toBe(false);
    });

    it("should return false for tampered signature", () => {
      const keyPair = generateEccKeyPair("secp256k1");
      const message = new TextEncoder().encode("Hello, World!");

      const signature = signEcdsa(message, keyPair.privateKey, "secp256k1");
      // 署名を改ざん
      const tamperedSignature = `${signature.signature.slice(0, -2)}00`;

      const isValid = verifyEcdsa(message, tamperedSignature, keyPair.publicKey, "secp256k1");
      expect(isValid).toBe(false);
    });

    it("should not verify with wrong key pair", () => {
      const keyPair1 = generateEccKeyPair("secp256k1");
      const keyPair2 = generateEccKeyPair("secp256k1");
      const message = new TextEncoder().encode("test");

      const signature = signEcdsa(message, keyPair1.privateKey, "secp256k1");
      const isValid = verifyEcdsa(message, signature.signature, keyPair2.publicKey, "secp256k1");
      expect(isValid).toBe(false);
    });
  });

  describe("signEddsa and verifyEddsa", () => {
    it("should sign and verify data correctly with ed25519", () => {
      const keyPair = generateEccKeyPair("ed25519");
      const message = new TextEncoder().encode("Hello, World!");

      const signature = signEddsa(message, keyPair.privateKey, "ed25519");
      expect(signature.signature).toBeDefined();
      expect(signature.signature.length).toBeGreaterThan(0);

      const isValid = verifyEddsa(message, signature.signature, keyPair.publicKey, "ed25519");
      expect(isValid).toBe(true);
    });

    it("should sign and verify data correctly with ed448", () => {
      const keyPair = generateEccKeyPair("ed448");
      const message = new TextEncoder().encode("Hello, World!");

      const signature = signEddsa(message, keyPair.privateKey, "ed448");
      const isValid = verifyEddsa(message, signature.signature, keyPair.publicKey, "ed448");
      expect(isValid).toBe(true);
    });

    it("should return false for tampered message with ed25519", () => {
      const keyPair = generateEccKeyPair("ed25519");
      const message = new TextEncoder().encode("Hello, World!");
      const tamperedMessage = new TextEncoder().encode("Hello, World?!");

      const signature = signEddsa(message, keyPair.privateKey, "ed25519");
      const isValid = verifyEddsa(
        tamperedMessage,
        signature.signature,
        keyPair.publicKey,
        "ed25519"
      );
      expect(isValid).toBe(false);
    });
  });

  describe("computeEcdh", () => {
    it("should compute shared secret with secp256k1", () => {
      const keyPair1 = generateEccKeyPair("secp256k1");
      const keyPair2 = generateEccKeyPair("secp256k1");

      const sharedSecret1 = computeEcdh(keyPair1.privateKey, keyPair2.publicKey, "secp256k1");
      const sharedSecret2 = computeEcdh(keyPair2.privateKey, keyPair1.publicKey, "secp256k1");

      expect(sharedSecret1.sharedSecret).toBe(sharedSecret2.sharedSecret);
      expect(sharedSecret1.sharedSecret.length).toBeGreaterThan(0);
    });

    it("should compute shared secret with p256", () => {
      const keyPair1 = generateEccKeyPair("p256");
      const keyPair2 = generateEccKeyPair("p256");

      const sharedSecret1 = computeEcdh(keyPair1.privateKey, keyPair2.publicKey, "p256");
      const sharedSecret2 = computeEcdh(keyPair2.privateKey, keyPair1.publicKey, "p256");

      expect(sharedSecret1.sharedSecret).toBe(sharedSecret2.sharedSecret);
    });

    it("should throw error for ed25519 (ECDH not supported)", () => {
      const keyPair1 = generateEccKeyPair("ed25519");
      const keyPair2 = generateEccKeyPair("ed25519");

      // 型アサーションを使用してテスト（実際の使用では型エラーになる）
      expect(() =>
        computeEcdh(keyPair1.privateKey, keyPair2.publicKey, "ed25519" as any)
      ).toThrow("ECDH is not supported");
    });
  });
});
