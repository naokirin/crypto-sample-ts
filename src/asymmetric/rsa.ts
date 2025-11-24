/**
 * RSA (Rivest-Shamir-Adleman) のサンプル実装
 *
 * RSAは、非対称鍵暗号の一種で、公開鍵暗号方式の代表的なアルゴリズムです。
 * 公開鍵で暗号化したデータは、対応する秘密鍵でのみ復号できます。
 * また、秘密鍵で署名したデータは、対応する公開鍵で検証できます。
 *
 * この実装では、RSA-OAEP（Optimal Asymmetric Encryption Padding）を使用します。
 * OAEPは、RSAの脆弱性を防ぐためのパディング方式です。
 */

import forge from "node-forge";

/**
 * RSA鍵のビット長
 */
export const RSA_KEY_SIZE_2048 = 2048;
export const RSA_KEY_SIZE_4096 = 4096;

/**
 * RSA鍵ペア
 */
export interface RsaKeyPair {
  /** 公開鍵（PEM形式） */
  publicKey: string;
  /** 秘密鍵（PEM形式） */
  privateKey: string;
}

/**
 * RSA-OAEPによる暗号化結果
 */
export interface RsaEncryptionResult {
  /** 暗号文（16進数文字列） */
  ciphertext: string;
}

/**
 * RSA署名結果
 */
export interface RsaSignatureResult {
  /** 署名（16進数文字列） */
  signature: string;
}

/**
 * RSA鍵ペアを生成します。
 *
 * @param keySize - 鍵のビット長（2048または4096）。デフォルトは2048。
 * @returns RSA鍵ペア（PEM形式）
 * @throws 鍵サイズが不正な場合にエラーをスローします。
 */
export function generateRsaKeyPair(keySize: number = RSA_KEY_SIZE_2048): RsaKeyPair {
  if (keySize !== RSA_KEY_SIZE_2048 && keySize !== RSA_KEY_SIZE_4096) {
    throw new Error(
      `Invalid key size: expected ${RSA_KEY_SIZE_2048} or ${RSA_KEY_SIZE_4096}, got ${keySize}`
    );
  }

  const keyPair = forge.pki.rsa.generateKeyPair(keySize);

  return {
    publicKey: forge.pki.publicKeyToPem(keyPair.publicKey),
    privateKey: forge.pki.privateKeyToPem(keyPair.privateKey),
  };
}

/**
 * RSA-OAEPを使用してデータを暗号化します。
 *
 * @param plaintext - 暗号化する平文（バイト配列）
 * @param publicKeyPem - 公開鍵（PEM形式）
 * @returns 暗号化結果（暗号文）
 * @throws 公開鍵が不正な場合、または暗号化に失敗した場合にエラーをスローします。
 */
export function encryptRSA(plaintext: Uint8Array, publicKeyPem: string): RsaEncryptionResult {
  try {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const plaintextBuffer = Buffer.from(plaintext);
    const encrypted = publicKey.encrypt(plaintextBuffer.toString("binary"), "RSA-OAEP");

    return {
      ciphertext: Buffer.from(encrypted, "binary").toString("hex"),
    };
  } catch (error) {
    throw new Error(
      `RSA encryption failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * RSA-OAEPを使用してデータを復号します。
 *
 * @param ciphertextHex - 復号する暗号文（16進数文字列）
 * @param privateKeyPem - 秘密鍵（PEM形式）
 * @returns 復号された平文（バイト配列）
 * @throws 秘密鍵が不正な場合、または復号に失敗した場合にエラーをスローします。
 */
export function decryptRSA(ciphertextHex: string, privateKeyPem: string): Uint8Array {
  try {
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const ciphertext = Buffer.from(ciphertextHex, "hex").toString("binary");
    const decrypted = privateKey.decrypt(ciphertext, "RSA-OAEP");

    // バイナリ文字列をUint8Arrayに変換
    const decryptedBytes = new Uint8Array(decrypted.length);
    for (let i = 0; i < decrypted.length; i++) {
      decryptedBytes[i] = decrypted.charCodeAt(i);
    }

    return decryptedBytes;
  } catch (error) {
    throw new Error(
      `RSA decryption failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * RSAを使用してデータに署名します。
 *
 * @param message - 署名するメッセージ（バイト配列）
 * @param privateKeyPem - 秘密鍵（PEM形式）
 * @param algorithm - ハッシュアルゴリズム（デフォルト: SHA-256）
 * @returns 署名結果
 * @throws 秘密鍵が不正な場合、または署名に失敗した場合にエラーをスローします。
 */
export function signRSA(
  message: Uint8Array,
  privateKeyPem: string,
  algorithm = "SHA-256"
): RsaSignatureResult {
  try {
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const messageBuffer = Buffer.from(message);
    const algName = algorithm.toLowerCase().replace("-", "");
    let md: forge.md.MessageDigest;
    if (algName === "sha256") {
      md = forge.md.sha256.create();
    } else if (algName === "sha384") {
      md = forge.md.sha384.create();
    } else if (algName === "sha512") {
      md = forge.md.sha512.create();
    } else if (algName === "sha1") {
      md = forge.md.sha1.create();
    } else {
      throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }
    md.update(messageBuffer.toString("binary"), "raw");

    const signature = privateKey.sign(md);

    return {
      signature: Buffer.from(signature, "binary").toString("hex"),
    };
  } catch (error) {
    throw new Error(
      `RSA signing failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * RSAを使用して署名を検証します。
 *
 * @param message - 検証するメッセージ（バイト配列）
 * @param signatureHex - 署名（16進数文字列）
 * @param publicKeyPem - 公開鍵（PEM形式）
 * @param algorithm - ハッシュアルゴリズム（デフォルト: SHA-256）
 * @returns 署名が有効な場合true、無効な場合false
 * @throws 公開鍵が不正な場合、または検証処理に失敗した場合にエラーをスローします。
 */
export function verifyRSA(
  message: Uint8Array,
  signatureHex: string,
  publicKeyPem: string,
  algorithm = "SHA-256"
): boolean {
  try {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const messageBuffer = Buffer.from(message);
    const algName = algorithm.toLowerCase().replace("-", "");
    let md: forge.md.MessageDigest;
    if (algName === "sha256") {
      md = forge.md.sha256.create();
    } else if (algName === "sha384") {
      md = forge.md.sha384.create();
    } else if (algName === "sha512") {
      md = forge.md.sha512.create();
    } else if (algName === "sha1") {
      md = forge.md.sha1.create();
    } else {
      throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }
    md.update(messageBuffer.toString("binary"), "raw");

    const signature = Buffer.from(signatureHex, "hex").toString("binary");
    const isValid = publicKey.verify(md.digest().bytes(), signature);

    return isValid;
  } catch (error) {
    // 無効な署名や間違った鍵ペアの場合はfalseを返す
    // 公開鍵のパースエラーなどの場合はエラーをスロー
    if (error instanceof Error && error.message.includes("Encryption block is invalid")) {
      return false;
    }
    throw new Error(
      `RSA verification failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * PEM形式の公開鍵をインポートします。
 *
 * @param publicKeyPem - 公開鍵（PEM形式）
 * @returns 公開鍵オブジェクト（node-forge）
 * @throws 公開鍵が不正な場合にエラーをスローします。
 */
export function importPublicKey(publicKeyPem: string): forge.pki.rsa.PublicKey {
  try {
    return forge.pki.publicKeyFromPem(publicKeyPem);
  } catch (error) {
    throw new Error(
      `Failed to import public key: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * PEM形式の秘密鍵をインポートします。
 *
 * @param privateKeyPem - 秘密鍵（PEM形式）
 * @returns 秘密鍵オブジェクト（node-forge）
 * @throws 秘密鍵が不正な場合にエラーをスローします。
 */
export function importPrivateKey(privateKeyPem: string): forge.pki.rsa.PrivateKey {
  try {
    return forge.pki.privateKeyFromPem(privateKeyPem);
  } catch (error) {
    throw new Error(
      `Failed to import private key: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
