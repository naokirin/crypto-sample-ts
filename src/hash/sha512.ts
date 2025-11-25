/**
 * SHA-512 (Secure Hash Algorithm 512-bit) のサンプル実装
 *
 * SHA-512は、SHA-2ファミリーの一つで、512ビット（64バイト）のハッシュ値を生成します。
 * SHA-256よりも長い出力を持ち、より高いセキュリティマージンを提供します。
 *
 * ## 特徴
 * - 出力サイズ: 512ビット（64バイト）
 * - ブロックサイズ: 1024ビット（128バイト）
 * - 構造: Merkle-Damgård構造（SHA-256と同じ）
 * - セキュリティ: 現在、実用的な攻撃は知られていない
 *
 * ## SHA-256との違い
 * - 内部演算が64ビット（SHA-256は32ビット）
 * - 64ビットプラットフォームでは高速
 * - より長い出力により、誕生日攻撃への耐性が高い
 *
 * ## 用途
 * - ファイルの完全性検証（大きなファイル）
 * - デジタル署名（より高いセキュリティが必要な場合）
 * - パスワードのハッシュ化（ソルト付き）
 * - 暗号学的な鍵導出
 *
 * ## 実装
 * この実装は、ブラウザのWeb Crypto APIを使用しています。
 */

import type { HashAlgorithmInfo } from "./index.js";

/**
 * SHA-512の出力サイズ（ビット）
 */
export const SHA512_OUTPUT_SIZE = 512;

/**
 * SHA-512のブロックサイズ（ビット）
 */
export const SHA512_BLOCK_SIZE = 1024;

/**
 * SHA-512アルゴリズムの情報
 */
export const SHA512_INFO: HashAlgorithmInfo = {
  name: "SHA-512",
  outputSize: SHA512_OUTPUT_SIZE,
  blockSize: SHA512_BLOCK_SIZE,
  description:
    "SHA-512は、SHA-2ファミリーの一つで、512ビットのハッシュ値を生成します。SHA-256よりも長い出力により、より高いセキュリティマージンを提供します。",
  keyed: false,
  securityLevel: "secure",
  useCase:
    "ファイル完全性検証、デジタル署名（高セキュリティ）、鍵導出関数",
};

/**
 * SHA-512ハッシュ関数
 *
 * Web Crypto APIを使用してSHA-512ハッシュを計算します。
 *
 * @param input - ハッシュ化する入力データ
 * @returns SHA-512ハッシュ値（64バイト）
 *
 * @example
 * ```typescript
 * const input = new TextEncoder().encode("Hello, World!");
 * const hash = await hashSHA512(input);
 * console.log(bytesToHex(hash)); // "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6c..."
 * ```
 */
export async function hashSHA512(input: Uint8Array): Promise<Uint8Array> {
  // Web Crypto APIを使用してSHA-512ハッシュを計算
  const hashBuffer = await crypto.subtle.digest("SHA-512", input);

  // ArrayBufferをUint8Arrayに変換
  return new Uint8Array(hashBuffer);
}
