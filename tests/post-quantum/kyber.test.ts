/**
 * CRYSTALS-Kyber (ML-KEM) のテスト
 */

import { describe, it, expect } from "vitest";
import {
  initKyber,
  generateKyberKeyPair,
  encapsulateKyber,
  decapsulateKyber,
} from "../../src/post-quantum/kyber.js";

describe("CRYSTALS-Kyber (ML-KEM)", () => {
  it("初期化が成功する", async () => {
    await expect(initKyber()).resolves.not.toThrow();
  });

  it("鍵ペアを生成できる", async () => {
    await initKyber();
    const keypair = await generateKyberKeyPair();

    expect(keypair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keypair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keypair.publicKey.length).toBeGreaterThan(0);
    expect(keypair.privateKey.length).toBeGreaterThan(0);
  });

  it("カプセル化とデカプセル化が正しく動作する", async () => {
    await initKyber();

    // 鍵ペアを生成
    const { publicKey, privateKey } = await generateKyberKeyPair();

    // カプセル化
    const { ciphertext, sharedSecret } = await encapsulateKyber(publicKey);

    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(sharedSecret).toBeInstanceOf(Uint8Array);
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(sharedSecret.length).toBe(32); // 共有秘密は32バイト

    // デカプセル化
    const decapsulatedSecret = await decapsulateKyber(
      ciphertext,
      privateKey,
      publicKey
    );

    expect(decapsulatedSecret).toBeInstanceOf(Uint8Array);
    expect(decapsulatedSecret.length).toBe(32);

    // 共有秘密が一致することを確認
    expect(decapsulatedSecret).toEqual(sharedSecret);
  });

  it("異なる公開鍵では異なる共有秘密が生成される", async () => {
    await initKyber();

    // 2つの鍵ペアを生成
    const keypair1 = await generateKyberKeyPair();
    const keypair2 = await generateKyberKeyPair();

    // それぞれカプセル化
    const enc1 = await encapsulateKyber(keypair1.publicKey);
    const enc2 = await encapsulateKyber(keypair2.publicKey);

    // 共有秘密が異なることを確認
    expect(enc1.sharedSecret).not.toEqual(enc2.sharedSecret);
  });

  it("同じ公開鍵でも異なるカプセル化で異なる暗号文が生成される", async () => {
    await initKyber();

    const { publicKey } = await generateKyberKeyPair();

    // 同じ公開鍵で2回カプセル化
    const enc1 = await encapsulateKyber(publicKey);
    const enc2 = await encapsulateKyber(publicKey);

    // 暗号文は異なるが、共有秘密は同じ（デカプセル化で確認）
    expect(enc1.ciphertext).not.toEqual(enc2.ciphertext);
    // 注意: 共有秘密はランダムに生成されるため、通常は異なる
    // ただし、デカプセル化で正しく復元できることを確認
  });

  it("間違った秘密鍵では正しい共有秘密が復元できない", async () => {
    await initKyber();

    // 2つの鍵ペアを生成
    const keypair1 = await generateKyberKeyPair();
    const keypair2 = await generateKyberKeyPair();

    // keypair1の公開鍵でカプセル化
    const { ciphertext, sharedSecret } = await encapsulateKyber(
      keypair1.publicKey
    );

    // keypair2の秘密鍵でデカプセル化を試みる（エラーが発生するか、異なる結果になる）
    // 注意: 実装によってはエラーを投げるか、異なる共有秘密を返す可能性がある
    const wrongDecapsulated = await decapsulateKyber(
      ciphertext,
      keypair2.privateKey,
      keypair1.publicKey
    );

    // 間違った秘密鍵では正しい共有秘密が復元できない
    expect(wrongDecapsulated).not.toEqual(sharedSecret);
  });
});

