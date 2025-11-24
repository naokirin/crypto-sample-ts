/**
 * Poly1305 (MAC) のサンプル実装
 *
 * Poly1305は、Daniel J. Bernsteinによって設計されたメッセージ認証コード（MAC）です。
 * 128ビットの認証タグを生成し、データの完全性と真正性を保証します。
 * 通常、ChaCha20やAESなどのストリーム暗号と組み合わせて使用されます
 * （例：ChaCha20-Poly1305、AES-GCM）。
 *
 * この実装では、Poly1305を単独で使用する例を示します。
 * 実際の使用では、暗号化と組み合わせた認証付き暗号（AEAD）を使用することが推奨されます。
 */

import { poly1305 } from "@noble/ciphers/_poly1305.js";
import { randomBytes } from "@noble/ciphers/utils.js";

/**
 * Poly1305の鍵長（バイト）
 * Poly1305は256ビット（32バイト）の鍵を使用します。
 */
export const POLY1305_KEY_LENGTH = 32;

/**
 * Poly1305の認証タグ長（バイト）
 * Poly1305は128ビット（16バイト）の認証タグを生成します。
 */
export const POLY1305_TAG_LENGTH = 16;

/**
 * Poly1305を使用してメッセージ認証コード（MAC）を計算します。
 *
 * @param message - MACを計算するメッセージ
 * @param key - MAC計算に使用する鍵（32バイト）
 * @returns 認証タグ（16バイト）
 * @throws 鍵の長さが不正な場合にエラーをスローします。
 */
export function computePoly1305MAC(message: Uint8Array, key: Uint8Array): Uint8Array {
  // 鍵の長さを検証
  if (key.length !== POLY1305_KEY_LENGTH) {
    throw new Error(`Invalid key length: expected ${POLY1305_KEY_LENGTH} bytes, got ${key.length}`);
  }

  // Poly1305インスタンスを作成
  const mac = poly1305.create(key);

  // メッセージを更新
  mac.update(message);

  // 認証タグを計算
  const tag = mac.digest();

  return tag;
}

/**
 * Poly1305を使用してメッセージ認証コード（MAC）を検証します。
 *
 * @param message - 検証するメッセージ
 * @param key - MAC検証に使用する鍵（32バイト）
 * @param tag - 検証する認証タグ（16バイト）
 * @returns 認証が成功した場合はtrue、失敗した場合はfalse
 * @throws 鍵または認証タグの長さが不正な場合にエラーをスローします。
 */
export function verifyPoly1305MAC(message: Uint8Array, key: Uint8Array, tag: Uint8Array): boolean {
  // 鍵の長さを検証
  if (key.length !== POLY1305_KEY_LENGTH) {
    throw new Error(`Invalid key length: expected ${POLY1305_KEY_LENGTH} bytes, got ${key.length}`);
  }

  // 認証タグの長さを検証
  if (tag.length !== POLY1305_TAG_LENGTH) {
    throw new Error(`Invalid tag length: expected ${POLY1305_TAG_LENGTH} bytes, got ${tag.length}`);
  }

  // メッセージからMACを再計算
  const computedTag = computePoly1305MAC(message, key);

  // 認証タグを比較（タイミング攻撃を防ぐため、定時間比較を使用）
  return constantTimeEqual(computedTag, tag);
}

/**
 * 2つのバイト配列を定時間で比較します。
 * タイミング攻撃を防ぐために、すべてのバイトを比較します。
 *
 * @param a - 比較する最初のバイト配列
 * @param b - 比較する2番目のバイト配列
 * @returns 2つの配列が等しい場合はtrue、そうでない場合はfalse
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

/**
 * ランダムなPoly1305鍵を生成します。
 *
 * @returns 32バイトのランダムな鍵
 */
export function generatePoly1305Key(): Uint8Array {
  return randomBytes(POLY1305_KEY_LENGTH);
}
