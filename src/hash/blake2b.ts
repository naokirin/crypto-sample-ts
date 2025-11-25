/**
 * BLAKE2b (BLAKE2 with 64-bit words) のサンプル実装
 *
 * BLAKE2は、SHA-3コンペティションのファイナリストであったBLAKEを改良した
 * 高速かつ安全なハッシュ関数です。SHA-3よりも高速で、MD5よりも安全です。
 *
 * ## 特徴
 * - 出力サイズ: 可変（デフォルト512ビット / 64バイト）
 * - ブロックサイズ: 1024ビット（128バイト）
 * - 構造: HAIFA構造（HAsh Iterative FrAmework）
 * - セキュリティ: 現在、実用的な攻撃は知られていない
 *
 * ## 利点
 * - SHA-3やSHA-2よりも高速（特にソフトウェア実装）
 * - 可変長出力（1〜64バイト）
 * - オプションで鍵付きハッシュ（MAC）としても使用可能
 * - ツリーハッシングのサポート（並列計算）
 *
 * ## BLAKEファミリー
 * - BLAKE2b: 64ビットプラットフォーム向け、最大512ビット出力
 * - BLAKE2s: 32ビットプラットフォーム向け、最大256ビット出力
 * - BLAKE3: 並列化に最適化された最新版
 *
 * ## 用途
 * - ファイルの完全性検証（SHA-2/SHA-3の代替）
 * - デジタル署名
 * - パスワードのハッシュ化（Argon2の内部で使用）
 * - 暗号通貨（Zcashなど）
 *
 * ## 実装
 * この実装は、@noble/hashesライブラリを使用しています。
 */

import { blake2b } from "@noble/hashes/blake2b";
import type { HashAlgorithmInfo } from "./index.js";

/**
 * BLAKE2bの出力サイズ（ビット）
 * デフォルトの512ビット（64バイト）を使用
 */
export const BLAKE2B_OUTPUT_SIZE = 512;

/**
 * BLAKE2bのブロックサイズ（ビット）
 */
export const BLAKE2B_BLOCK_SIZE = 1024;

/**
 * BLAKE2bアルゴリズムの情報
 */
export const BLAKE2B_INFO: HashAlgorithmInfo = {
  name: "BLAKE2b",
  outputSize: BLAKE2B_OUTPUT_SIZE,
  blockSize: BLAKE2B_BLOCK_SIZE,
  description:
    "BLAKE2bは、SHA-3ファイナリストBLAKEの改良版で、SHA-3よりも高速かつ安全なハッシュ関数です。Argon2パスワードハッシュやZcash暗号通貨で使用されています。",
  keyed: false,
  securityLevel: "secure",
  useCase:
    "ファイル完全性検証、デジタル署名、パスワードハッシュ、暗号通貨",
};

/**
 * BLAKE2bハッシュ関数
 *
 * @noble/hashesライブラリを使用してBLAKE2bハッシュを計算します。
 * デフォルトで512ビット（64バイト）のハッシュ値を生成します。
 *
 * @param input - ハッシュ化する入力データ
 * @returns BLAKE2bハッシュ値（64バイト）
 *
 * @example
 * ```typescript
 * const input = new TextEncoder().encode("Hello, World!");
 * const hash = await hashBLAKE2b(input);
 * console.log(bytesToHex(hash)); // "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbc..."
 * ```
 */
export async function hashBLAKE2b(input: Uint8Array): Promise<Uint8Array> {
  // @noble/hashesのblake2bは同期関数なので、Promiseでラップ
  // デフォルトの64バイト（512ビット）出力を使用
  return Promise.resolve(blake2b(input));
}
