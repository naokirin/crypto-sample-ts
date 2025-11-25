/**
 * SHA-3-256 (Secure Hash Algorithm 3, 256-bit) のサンプル実装
 *
 * SHA-3は、NISTが2015年に標準化した最新の暗号学的ハッシュ関数です。
 * Keccakアルゴリズムをベースにしており、SHA-2とは完全に異なる内部構造を持ちます。
 *
 * ## 特徴
 * - 出力サイズ: 256ビット（32バイト）
 * - ブロックサイズ: 1088ビット（136バイト）※スポンジ構造のレート
 * - 構造: スポンジ構造（Merkle-Damgård構造とは異なる）
 * - セキュリティ: 現在、実用的な攻撃は知られていない
 *
 * ## SHA-2との違い
 * - 内部構造が完全に異なる（スポンジ構造 vs Merkle-Damgård構造）
 * - 長さ拡張攻撃に対して本質的に耐性がある
 * - NIST SHA-3コンペティション（2007-2012）の勝者
 *
 * ## スポンジ構造とは
 * 1. 吸収フェーズ: 入力データを少しずつ内部状態に「吸収」
 * 2. 絞り出しフェーズ: 内部状態から出力を「絞り出す」
 * この構造により、任意長の入力から任意長の出力を生成できます。
 *
 * ## 用途
 * - ファイルの完全性検証
 * - デジタル署名
 * - 暗号学的な鍵導出
 * - SHA-2の代替（多様性のため）
 *
 * ## 実装
 * この実装は、@noble/hashesライブラリを使用しています。
 * Web Crypto APIはまだSHA-3をサポートしていないため、
 * セキュリティ監査済みのJavaScript実装を使用しています。
 */

import { sha3_256 } from "@noble/hashes/sha3";
import type { HashAlgorithmInfo } from "./index.js";

/**
 * SHA-3-256の出力サイズ（ビット）
 */
export const SHA3_256_OUTPUT_SIZE = 256;

/**
 * SHA-3-256のブロックサイズ（ビット）
 * ※スポンジ構造のレート（rate）パラメータ
 */
export const SHA3_256_BLOCK_SIZE = 1088;

/**
 * SHA-3-256アルゴリズムの情報
 */
export const SHA3_256_INFO: HashAlgorithmInfo = {
  name: "SHA-3-256",
  outputSize: SHA3_256_OUTPUT_SIZE,
  blockSize: SHA3_256_BLOCK_SIZE,
  description:
    "SHA-3-256は、NIST標準の最新ハッシュ関数です。Keccakアルゴリズムをベースにしたスポンジ構造を持ち、SHA-2とは完全に異なる設計です。",
  keyed: false,
  securityLevel: "secure",
  useCase:
    "ファイル完全性検証、デジタル署名、鍵導出関数、SHA-2の代替",
};

/**
 * SHA-3-256ハッシュ関数
 *
 * @noble/hashesライブラリを使用してSHA-3-256ハッシュを計算します。
 *
 * @param input - ハッシュ化する入力データ
 * @returns SHA-3-256ハッシュ値（32バイト）
 *
 * @example
 * ```typescript
 * const input = new TextEncoder().encode("Hello, World!");
 * const hash = await hashSHA3_256(input);
 * console.log(bytesToHex(hash)); // "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef"
 * ```
 */
export async function hashSHA3_256(input: Uint8Array): Promise<Uint8Array> {
  // @noble/hashesのsha3_256は同期関数なので、Promiseでラップ
  return Promise.resolve(sha3_256(input));
}
