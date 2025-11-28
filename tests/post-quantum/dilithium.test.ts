/**
 * CRYSTALS-Dilithium (ML-DSA) のテスト
 */

import { describe, it, expect } from "vitest";
import {
  initDilithium,
  generateDilithiumKeyPair,
  signDilithium,
  verifyDilithium,
} from "../../src/post-quantum/dilithium.js";

describe("CRYSTALS-Dilithium (ML-DSA)", () => {
  it("初期化が成功する", async () => {
    await expect(initDilithium()).resolves.not.toThrow();
  });

  it("鍵ペアを生成できる", async () => {
    await initDilithium();
    const keypair = await generateDilithiumKeyPair();

    expect(keypair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keypair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keypair.publicKey.length).toBeGreaterThan(0);
    expect(keypair.privateKey.length).toBeGreaterThan(0);
  });

  it("署名と検証が正しく動作する", async () => {
    await initDilithium();

    // 鍵ペアを生成
    const { publicKey, privateKey } = await generateDilithiumKeyPair();

    // メッセージを準備
    const message = new TextEncoder().encode("Hello, Dilithium!");

    // 署名を生成
    const signature = await signDilithium(message, privateKey);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBeGreaterThan(0);

    // 署名を検証
    const isValid = await verifyDilithium(message, signature, publicKey);

    expect(isValid).toBe(true);
  });

  it("異なるメッセージでは署名が無効になる", async () => {
    await initDilithium();

    const { publicKey, privateKey } = await generateDilithiumKeyPair();

    const message1 = new TextEncoder().encode("Message 1");
    const message2 = new TextEncoder().encode("Message 2");

    const signature = await signDilithium(message1, privateKey);

    // 異なるメッセージで検証
    const isValid = await verifyDilithium(message2, signature, publicKey);

    expect(isValid).toBe(false);
  });

  it("異なる公開鍵では署名が無効になる", async () => {
    await initDilithium();

    // 2つの鍵ペアを生成
    const keypair1 = await generateDilithiumKeyPair();
    const keypair2 = await generateDilithiumKeyPair();

    const message = new TextEncoder().encode("Test message");

    // keypair1で署名
    const signature = await signDilithium(message, keypair1.privateKey);

    // keypair2の公開鍵で検証（無効になるはず）
    const isValid = await verifyDilithium(message, signature, keypair2.publicKey);

    expect(isValid).toBe(false);
  });

  it("同じメッセージでも異なる署名が生成される", async () => {
    await initDilithium();

    const { publicKey, privateKey } = await generateDilithiumKeyPair();
    const message = new TextEncoder().encode("Same message");

    // 同じメッセージで2回署名
    const signature1 = await signDilithium(message, privateKey);
    const signature2 = await signDilithium(message, privateKey);

    // 署名は異なるが、どちらも有効
    expect(signature1).not.toEqual(signature2);

    // 同じ公開鍵で検証（どちらも有効であることを確認）
    const isValid1 = await verifyDilithium(message, signature1, publicKey);
    const isValid2 = await verifyDilithium(message, signature2, publicKey);

    expect(isValid1).toBe(true);
    expect(isValid2).toBe(true);
  });
});
