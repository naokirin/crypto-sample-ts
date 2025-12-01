/**
 * KP-ABE（Key-Policy Attribute-Based Encryption）の完全なテスト
 *
 * KP-ABEスキームの動作確認
 * KP-ABEでは、鍵生成時にポリシー（属性リスト）を指定し、
 * 暗号化時に属性セットを指定します。
 */

import { beforeAll, describe, expect, it } from "vitest";
import {
  decryptKPABE,
  encryptKPABE,
  extractKPABEKey,
  generateKPABEKeyPair,
  initABE,
} from "../../src/asymmetric/abe.js";

describe("KP-ABE Full Implementation", () => {
  beforeAll(async () => {
    // WebAssemblyモジュールを初期化
    await initABE();
  });

  it("should generate master key pair", async () => {
    const { masterKey, publicParams } = await generateKPABEKeyPair();

    expect(masterKey).toBeDefined();
    expect(publicParams).toBeDefined();
    expect(masterKey.secret.length).toBeGreaterThan(0);
    expect(publicParams.params.length).toBeGreaterThan(0);
  });

  it("should extract private key from policy", async () => {
    const { masterKey } = await generateKPABEKeyPair();
    const policy = "A,B,C";

    const privateKey = await extractKPABEKey(masterKey, policy);

    expect(privateKey).toBeDefined();
    expect(privateKey.key.length).toBeGreaterThan(0);
    expect(privateKey.attributes).toEqual(["A", "B", "C"]);
  });

  it("should encrypt and decrypt message", async () => {
    const { masterKey, publicParams } = await generateKPABEKeyPair();
    const policy = "A,B,C";
    const attributes = ["A", "B", "C"];
    const message = new TextEncoder().encode("Hello, KP-ABE!");

    // ポリシーから秘密鍵を生成
    const privateKey = await extractKPABEKey(masterKey, policy);

    // 属性セットでメッセージを暗号化
    const ciphertext = await encryptKPABE(publicParams, attributes, message);

    expect(ciphertext).toBeDefined();
    expect(ciphertext.length).toBeGreaterThan(0);

    // 暗号文を復号化
    const decrypted = await decryptKPABE(privateKey, ciphertext);

    expect(decrypted).toBeDefined();
    expect(new TextDecoder().decode(decrypted)).toBe("Hello, KP-ABE!");
  });

  it("should fail to decrypt with mismatched attributes", async () => {
    const { masterKey, publicParams } = await generateKPABEKeyPair();
    const policy = "A,B,C";
    const attributes1 = ["A", "B", "C"];
    const attributes2 = ["D", "E", "F"];
    const message = new TextEncoder().encode("Hello, KP-ABE!");

    // ポリシーから秘密鍵を生成
    const privateKey = await extractKPABEKey(masterKey, policy);

    // attributes2でメッセージを暗号化（ポリシーと一致しない）
    const ciphertext = await encryptKPABE(publicParams, attributes2, message);

    // 復号化を試みる（属性が一致しないため失敗するはず）
    await expect(decryptKPABE(privateKey, ciphertext)).rejects.toThrow();
  });

  it("should handle single attribute", async () => {
    const { masterKey, publicParams } = await generateKPABEKeyPair();
    const policy = "A";
    const attributes = ["A"];
    const message = new TextEncoder().encode("Single attribute test");

    const privateKey = await extractKPABEKey(masterKey, policy);
    const ciphertext = await encryptKPABE(publicParams, attributes, message);
    const decrypted = await decryptKPABE(privateKey, ciphertext);

    expect(new TextDecoder().decode(decrypted)).toBe("Single attribute test");
  });

  it("should handle multiple attributes", async () => {
    const { masterKey, publicParams } = await generateKPABEKeyPair();
    const policy = "A,B,C,D,E";
    const attributes = ["A", "B", "C", "D", "E"];
    const message = new TextEncoder().encode("Multiple attributes test");

    const privateKey = await extractKPABEKey(masterKey, policy);
    const ciphertext = await encryptKPABE(publicParams, attributes, message);
    const decrypted = await decryptKPABE(privateKey, ciphertext);

    expect(new TextDecoder().decode(decrypted)).toBe("Multiple attributes test");
  });
});

