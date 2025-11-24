/**
 * ChaCha20 のサンプル実装
 *
 * ChaCha20は、ストリーム暗号の一種で、Daniel J. Bernsteinによって設計されました。
 * Salsa20の改良版であり、高いセキュリティとパフォーマンスを提供します。
 * この実装では、XChaCha20-Poly1305を使用します。
 * XChaCha20は、ChaCha20の拡張版で、192ビット（24バイト）のノンスを使用します。
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";

/**
 * XChaCha20の鍵長（ビット）
 */
export const CHACHA20_KEY_LENGTH = 256; // 256ビット = 32バイト

/**
 * XChaCha20のノンス長（バイト）
 * XChaCha20では192ビット（24バイト）のノンスを使用します。
 */
export const CHACHA20_NONCE_LENGTH = 24;

/**
 * Poly1305の認証タグ長（バイト）
 * Poly1305は128ビット（16バイト）の認証タグを生成します。
 */
export const POLY1305_TAG_LENGTH = 16;

/**
 * XChaCha20-Poly1305による暗号化結果
 */
export interface ChaCha20EncryptionResult {
  /** 暗号文 */
  ciphertext: Uint8Array;
  /** 認証タグ */
  authTag: Uint8Array;
  /** ノンス */
  nonce: Uint8Array;
}

/**
 * XChaCha20-Poly1305を使用してデータを暗号化します。
 *
 * @param plaintext - 暗号化する平文
 * @param key - 暗号化に使用する鍵（32バイト）
 * @param nonce - ノンス（24バイト）。指定しない場合はランダムに生成されます。
 * @returns 暗号化結果（暗号文、認証タグ、ノンス）
 * @throws 鍵またはノンスの長さが不正な場合にエラーをスローします。
 */
export function encryptChaCha20(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce?: Uint8Array
): ChaCha20EncryptionResult {
  // 鍵の長さを検証（256ビット = 32バイト）
  if (key.length !== CHACHA20_KEY_LENGTH / 8) {
    throw new Error(
      `Invalid key length: expected ${CHACHA20_KEY_LENGTH / 8} bytes, got ${key.length}`
    );
  }

  // ノンスが指定されていない場合はランダムに生成
  const nonceValue = nonce ?? randomBytes(CHACHA20_NONCE_LENGTH);

  // ノンスの長さを検証
  if (nonceValue.length !== CHACHA20_NONCE_LENGTH) {
    throw new Error(
      `Invalid nonce length: expected ${CHACHA20_NONCE_LENGTH} bytes, got ${nonceValue.length}`
    );
  }

  // XChaCha20-Poly1305インスタンスを作成
  const cipher = xchacha20poly1305(key, nonceValue);

  // データを暗号化（認証タグは暗号文の末尾に含まれる）
  const encrypted = cipher.encrypt(plaintext);

  // 暗号文と認証タグを分離
  const ciphertext = encrypted.subarray(0, encrypted.length - POLY1305_TAG_LENGTH);
  const authTag = encrypted.subarray(encrypted.length - POLY1305_TAG_LENGTH);

  return {
    ciphertext,
    authTag,
    nonce: nonceValue,
  };
}

/**
 * XChaCha20-Poly1305を使用してデータを復号します。
 *
 * @param ciphertext - 復号する暗号文
 * @param key - 復号に使用する鍵（32バイト）
 * @param nonce - 暗号化時に使用したノンス（24バイト）
 * @param authTag - 暗号化時に生成された認証タグ（16バイト）
 * @returns 復号された平文
 * @throws 鍵、ノンス、認証タグの長さが不正な場合、または認証に失敗した場合にエラーをスローします。
 */
export function decryptChaCha20(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  authTag: Uint8Array
): Uint8Array {
  // 鍵の長さを検証
  if (key.length !== CHACHA20_KEY_LENGTH / 8) {
    throw new Error(
      `Invalid key length: expected ${CHACHA20_KEY_LENGTH / 8} bytes, got ${key.length}`
    );
  }

  // ノンスの長さを検証
  if (nonce.length !== CHACHA20_NONCE_LENGTH) {
    throw new Error(
      `Invalid nonce length: expected ${CHACHA20_NONCE_LENGTH} bytes, got ${nonce.length}`
    );
  }

  // 認証タグの長さを検証
  if (authTag.length !== POLY1305_TAG_LENGTH) {
    throw new Error(
      `Invalid auth tag length: expected ${POLY1305_TAG_LENGTH} bytes, got ${authTag.length}`
    );
  }

  // XChaCha20-Poly1305インスタンスを作成
  const cipher = xchacha20poly1305(key, nonce);

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
 * ランダムなChaCha20鍵を生成します。
 *
 * @returns 32バイト（256ビット）のランダムな鍵
 */
export function generateChaCha20Key(): Uint8Array {
  return randomBytes(CHACHA20_KEY_LENGTH / 8);
}
