import { describe, it, expect } from "vitest";
import {
  initFalcon,
  generateFalconKeyPair,
  signFalcon,
  verifyFalcon,
} from "../../src/post-quantum/falcon.js";

describe("FALCON (FN-DSA)", () => {
  it("初期化が成功する", async () => {
    await expect(initFalcon()).resolves.not.toThrow();
  });

  it("鍵ペアを生成できる", async () => {
    const keypair = await generateFalconKeyPair();
    expect(keypair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keypair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keypair.publicKey.length).toBeGreaterThan(0);
    expect(keypair.privateKey.length).toBeGreaterThan(0);
  });

  it("署名と検証が正しく動作する", async () => {
    const keypair = await generateFalconKeyPair();
    const message = new TextEncoder().encode("Hello, FALCON!");

    const signature = await signFalcon(message, keypair.privateKey);
    const isValid = await verifyFalcon(message, signature, keypair.publicKey);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBeGreaterThan(0);
    expect(isValid).toBe(true);
  });

  it("異なるメッセージでは検証が失敗する", async () => {
    const keypair = await generateFalconKeyPair();
    const message1 = new TextEncoder().encode("Message 1");
    const message2 = new TextEncoder().encode("Message 2");

    const signature = await signFalcon(message1, keypair.privateKey);
    const isValid = await verifyFalcon(message2, signature, keypair.publicKey);

    expect(isValid).toBe(false);
  });

  it("異なる公開鍵では検証が失敗する", async () => {
    const keypair1 = await generateFalconKeyPair();
    const keypair2 = await generateFalconKeyPair();
    const message = new TextEncoder().encode("Test message");

    const signature = await signFalcon(message, keypair1.privateKey);
    const isValid = await verifyFalcon(message, signature, keypair2.publicKey);

    expect(isValid).toBe(false);
  });

  it("同じメッセージでも異なる署名が生成される（確率的署名）", async () => {
    const keypair = await generateFalconKeyPair();
    const message = new TextEncoder().encode("Test message");

    const signature1 = await signFalcon(message, keypair.privateKey);
    const signature2 = await signFalcon(message, keypair.privateKey);

    // 署名は異なるが、両方とも検証に成功する
    expect(signature1).not.toEqual(signature2);

    const isValid1 = await verifyFalcon(message, signature1, keypair.publicKey);
    const isValid2 = await verifyFalcon(message, signature2, keypair.publicKey);

    expect(isValid1).toBe(true);
    expect(isValid2).toBe(true);
  });

  it("長いメッセージでも正しく動作する", async () => {
    const keypair = await generateFalconKeyPair();
    const longMessage = new TextEncoder().encode("A".repeat(10000));

    const signature = await signFalcon(longMessage, keypair.privateKey);
    const isValid = await verifyFalcon(longMessage, signature, keypair.publicKey);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBeGreaterThan(0);
    expect(isValid).toBe(true);
  });
});
