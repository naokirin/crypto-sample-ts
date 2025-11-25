/**
 * SHA-256 (Secure Hash Algorithm 256-bit) のサンプル実装
 *
 * SHA-256は、SHA-2ファミリーの一つで、256ビット（32バイト）のハッシュ値を生成します。
 * NIST（米国国立標準技術研究所）によって標準化された暗号学的ハッシュ関数です。
 *
 * ## 特徴
 * - 出力サイズ: 256ビット（32バイト）
 * - ブロックサイズ: 512ビット（64バイト）
 * - 構造: Merkle-Damgård構造
 * - セキュリティ: 現在、実用的な攻撃は知られていない
 *
 * ## 用途
 * - ファイルの完全性検証（チェックサム）
 * - デジタル署名
 * - パスワードのハッシュ化（ソルト付き）
 * - ブロックチェーン（Bitcoin等）
 * - SSL/TLS証明書
 *
 * ## 実装
 * この実装は、ブラウザのWeb Crypto APIを使用しています。
 * Web Crypto APIは、ネイティブコードで実装されているため、高速で安全です。
 */

import type { HashAlgorithmInfo } from "./index.js";

/**
 * SHA-256の出力サイズ（ビット）
 */
export const SHA256_OUTPUT_SIZE = 256;

/**
 * SHA-256のブロックサイズ（ビット）
 */
export const SHA256_BLOCK_SIZE = 512;

/**
 * SHA-256アルゴリズムの情報
 */
export const SHA256_INFO: HashAlgorithmInfo = {
  name: "SHA-256",
  outputSize: SHA256_OUTPUT_SIZE,
  blockSize: SHA256_BLOCK_SIZE,
  description:
    "SHA-256は、NIST標準の暗号学的ハッシュ関数で、256ビットのハッシュ値を生成します。Bitcoin等のブロックチェーンでも使用されています。",
  keyed: false,
  securityLevel: "secure",
  useCase: "ファイル完全性検証、デジタル署名、ブロックチェーン、SSL/TLS",
};

/**
 * SHA-256ハッシュ関数
 *
 * Web Crypto APIを使用してSHA-256ハッシュを計算します。
 *
 * @param input - ハッシュ化する入力データ
 * @returns SHA-256ハッシュ値（32バイト）
 *
 * @example
 * ```typescript
 * const input = new TextEncoder().encode("Hello, World!");
 * const hash = await hashSHA256(input);
 * console.log(bytesToHex(hash)); // "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
 * ```
 */
export async function hashSHA256(input: Uint8Array): Promise<Uint8Array> {
  // Web Crypto APIを使用してSHA-256ハッシュを計算
  const hashBuffer = await crypto.subtle.digest("SHA-256", input);

  // ArrayBufferをUint8Arrayに変換
  return new Uint8Array(hashBuffer);
}
