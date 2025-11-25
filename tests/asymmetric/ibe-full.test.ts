/**
 * IBE（Identity-Based Encryption）の完全なテスト
 *
 * Boneh-Franklin IBEスキームの動作確認
 */

import { beforeAll, describe, expect, it } from "vitest";
import {
  decryptIBE,
  encryptIBE,
  extractIBEKey,
  generateIBEKeyPair,
  initIBE,
} from "../../src/asymmetric/ibe.js";

describe("IBE Full Implementation", () => {
  beforeAll(async () => {
    // WebAssemblyモジュールを初期化
    await initIBE();
  });

  it("should generate master key pair", async () => {
    const { masterKey, publicParams } = await generateIBEKeyPair();

    expect(masterKey).toBeDefined();
    expect(publicParams).toBeDefined();
    expect(masterKey.secret.length).toBeGreaterThan(0);
    expect(publicParams.params.length).toBeGreaterThan(0);
  });

  it("should extract private key from identity", async () => {
    const { masterKey } = await generateIBEKeyPair();
    const identity = "user@example.com";

    const privateKey = await extractIBEKey(masterKey, identity);

    expect(privateKey).toBeDefined();
    expect(privateKey.key.length).toBeGreaterThan(0);
  });

  it("should encrypt and decrypt message", async () => {
    const { masterKey, publicParams } = await generateIBEKeyPair();
    const identity = "user@example.com";
    const message = new TextEncoder().encode("Hello, IBE!");

    // 秘密鍵を抽出
    const privateKey = await extractIBEKey(masterKey, identity);

    // メッセージを暗号化
    const ciphertext = await encryptIBE(publicParams, identity, message);

    expect(ciphertext).toBeDefined();
    expect(ciphertext.length).toBeGreaterThan(0);

    // 暗号文を復号化
    const decrypted = await decryptIBE(privateKey, ciphertext);

    expect(decrypted).toBeDefined();
    expect(new TextDecoder().decode(decrypted)).toBe("Hello, IBE!");
  });

  it("should fail to decrypt with wrong private key", async () => {
    const { masterKey, publicParams } = await generateIBEKeyPair();
    const identity1 = "user1@example.com";
    const identity2 = "user2@example.com";
    const message = new TextEncoder().encode("Hello, IBE!");

    // identity1で暗号化
    const ciphertext = await encryptIBE(publicParams, identity1, message);

    // identity2の秘密鍵で復号化を試みる（失敗するはず）
    const wrongPrivateKey = await extractIBEKey(masterKey, identity2);

    // 復号化は成功するが、結果は異なる（またはエラーになる）
    // 注意: Boneh-Franklinスキームでは、異なるアイデンティティの鍵でも
    // 復号化は技術的に可能だが、結果は無意味なデータになる
    const decrypted = await decryptIBE(wrongPrivateKey, ciphertext);

    // 復号化されたデータは元のメッセージと異なる
    expect(new TextDecoder().decode(decrypted)).not.toBe("Hello, IBE!");
  });
});
