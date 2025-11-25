/**
 * BLAKE3 のサンプル実装
 *
 * BLAKE3は、BLAKE2の後継として設計された最新のハッシュ関数です。
 * 並列計算に最適化されており、非常に高速です。
 *
 * ## 特徴
 * - 出力サイズ: 可変（デフォルト256ビット / 32バイト）
 * - ブロックサイズ: 1024ビット（128バイト）
 * - 構造: Merkleツリー構造（並列化可能）
 * - セキュリティ: 現在、実用的な攻撃は知られていない
 *
 * ## BLAKE2との違い
 * - 並列計算に最適化（マルチコアCPUで大幅に高速化）
 * - より単純な設計
 * - 無制限の出力長（拡張可能出力関数 / XOF）
 * - 鍵付きハッシュ（MAC）モードの簡素化
 *
 * ## 利点
 * - 極めて高速（MD5やSHA-1よりも高速な場合も）
 * - 並列計算が可能（複数のCPUコアを活用）
 * - ストリーミング可能（大きなファイルの処理に最適）
 * - 検証可能（Merkleツリーにより部分検証が可能）
 *
 * ## 用途
 * - ファイルの完全性検証（特に大きなファイル）
 * - デジタル署名
 * - コンテンツアドレス可能ストレージ（CAS）
 * - 並列計算が必要な場面
 *
 * ## 実装
 * この実装は、@noble/hashesライブラリを使用しています。
 */

import { blake3 } from "@noble/hashes/blake3";
import type { HashAlgorithmInfo } from "./index.js";

/**
 * BLAKE3の出力サイズ（ビット）
 * デフォルトの256ビット（32バイト）を使用
 */
export const BLAKE3_OUTPUT_SIZE = 256;

/**
 * BLAKE3のブロックサイズ（ビット）
 */
export const BLAKE3_BLOCK_SIZE = 1024;

/**
 * BLAKE3アルゴリズムの情報
 */
export const BLAKE3_INFO: HashAlgorithmInfo = {
  name: "BLAKE3",
  outputSize: BLAKE3_OUTPUT_SIZE,
  blockSize: BLAKE3_BLOCK_SIZE,
  description:
    "BLAKE3は、BLAKE2の後継として設計された最新のハッシュ関数です。並列計算に最適化されており、マルチコアCPUで極めて高速に動作します。",
  keyed: false,
  securityLevel: "secure",
  useCase:
    "ファイル完全性検証（大容量）、デジタル署名、並列計算、コンテンツアドレス可能ストレージ",
};

/**
 * BLAKE3ハッシュ関数
 *
 * @noble/hashesライブラリを使用してBLAKE3ハッシュを計算します。
 * デフォルトで256ビット（32バイト）のハッシュ値を生成します。
 *
 * @param input - ハッシュ化する入力データ
 * @returns BLAKE3ハッシュ値（32バイト）
 *
 * @example
 * ```typescript
 * const input = new TextEncoder().encode("Hello, World!");
 * const hash = await hashBLAKE3(input);
 * console.log(bytesToHex(hash)); // "ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d"
 * ```
 */
export async function hashBLAKE3(input: Uint8Array): Promise<Uint8Array> {
  // @noble/hashesのblake3は同期関数なので、Promiseでラップ
  // デフォルトの32バイト（256ビット）出力を使用
  return Promise.resolve(blake3(input));
}
