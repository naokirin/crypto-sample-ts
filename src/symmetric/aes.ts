/**
 * AES (Advanced Encryption Standard) のサンプル実装
 *
 * AESは、対称鍵暗号の一種で、128ビット、192ビット、256ビットの鍵長をサポートします。
 * この実装では、AES-GCM（Galois/Counter Mode）を使用します。
 * GCMは認証付き暗号（AEAD: Authenticated Encryption with Associated Data）の一種で、
 * 暗号化と同時に認証タグを生成し、データの完全性を保証します。
 */

import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";

/**
 * AES-GCMの鍵長（ビット）
 */
export const AES_KEY_LENGTH = 256; // 256ビット = 32バイト

/**
 * AES-GCMのIV（初期化ベクトル）長（バイト）
 * GCMモードでは通常96ビット（12バイト）のIVを使用します。
 */
export const AES_IV_LENGTH = 12;

/**
 * AES-GCMの認証タグ長（バイト）
 * 通常16バイト（128ビット）の認証タグを使用します。
 */
export const AES_TAG_LENGTH = 16;

/**
 * AES-GCMによる暗号化結果
 */
export interface AesEncryptionResult {
  /** 暗号文 */
  ciphertext: Uint8Array;
  /** 認証タグ */
  authTag: Uint8Array;
  /** 初期化ベクトル（IV） */
  iv: Uint8Array;
}

/**
 * AES-GCMを使用してデータを暗号化します。
 *
 * @param plaintext - 暗号化する平文
 * @param key - 暗号化に使用する鍵（32バイト）
 * @param iv - 初期化ベクトル（12バイト）。指定しない場合はランダムに生成されます。
 * @returns 暗号化結果（暗号文、認証タグ、IV）
 * @throws 鍵またはIVの長さが不正な場合にエラーをスローします。
 */
export function encryptAES(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array
): AesEncryptionResult {
  // 鍵の長さを検証（256ビット = 32バイト）
  if (key.length !== AES_KEY_LENGTH / 8) {
    throw new Error(`Invalid key length: expected ${AES_KEY_LENGTH / 8} bytes, got ${key.length}`);
  }

  // IVが指定されていない場合はランダムに生成
  const initializationVector = iv ?? randomBytes(AES_IV_LENGTH);

  // IVの長さを検証
  if (initializationVector.length !== AES_IV_LENGTH) {
    throw new Error(
      `Invalid IV length: expected ${AES_IV_LENGTH} bytes, got ${initializationVector.length}`
    );
  }

  // AES-GCMインスタンスを作成
  const cipher = gcm(key, initializationVector);

  // データを暗号化（認証タグは暗号文の末尾に含まれる）
  const encrypted = cipher.encrypt(plaintext);

  // 暗号文と認証タグを分離
  const ciphertext = encrypted.subarray(0, encrypted.length - AES_TAG_LENGTH);
  const authTag = encrypted.subarray(encrypted.length - AES_TAG_LENGTH);

  return {
    ciphertext,
    authTag,
    iv: initializationVector,
  };
}

/**
 * AES-GCMを使用してデータを復号します。
 *
 * @param ciphertext - 復号する暗号文
 * @param key - 復号に使用する鍵（32バイト）
 * @param iv - 暗号化時に使用した初期化ベクトル（12バイト）
 * @param authTag - 暗号化時に生成された認証タグ（16バイト）
 * @returns 復号された平文
 * @throws 鍵、IV、認証タグの長さが不正な場合、または認証に失敗した場合にエラーをスローします。
 */
export function decryptAES(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  authTag: Uint8Array
): Uint8Array {
  // 鍵の長さを検証
  if (key.length !== AES_KEY_LENGTH / 8) {
    throw new Error(`Invalid key length: expected ${AES_KEY_LENGTH / 8} bytes, got ${key.length}`);
  }

  // IVの長さを検証
  if (iv.length !== AES_IV_LENGTH) {
    throw new Error(`Invalid IV length: expected ${AES_IV_LENGTH} bytes, got ${iv.length}`);
  }

  // 認証タグの長さを検証
  if (authTag.length !== AES_TAG_LENGTH) {
    throw new Error(
      `Invalid auth tag length: expected ${AES_TAG_LENGTH} bytes, got ${authTag.length}`
    );
  }

  // AES-GCMインスタンスを作成
  const cipher = gcm(key, iv);

  // 暗号文と認証タグを結合（認証タグは暗号文の末尾に付ける必要がある）
  const ciphertextWithTag = new Uint8Array(ciphertext.length + authTag.length);
  ciphertextWithTag.set(ciphertext);
  ciphertextWithTag.set(authTag, ciphertext.length);

  // データを復号（認証も同時に実行される）
  try {
    const plaintext = cipher.decrypt(ciphertextWithTag);
    return plaintext;
  } catch (error) {
    // 認証に失敗した場合（データが改ざんされている可能性）
    throw new Error("Authentication failed: data may have been tampered with");
  }
}

/**
 * ランダムなAES鍵を生成します。
 *
 * @returns 32バイト（256ビット）のランダムな鍵
 */
export function generateAESKey(): Uint8Array {
  return randomBytes(AES_KEY_LENGTH / 8);
}
