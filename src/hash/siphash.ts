/**
 * SipHash-2-4 のサンプル実装
 *
 * SipHashは、鍵付きハッシュ関数（MAC: Message Authentication Code）です。
 * 暗号学的ハッシュ関数（SHA-256等）とは異なり、秘密鍵を使用します。
 *
 * ## 重要な違い: 暗号学的ハッシュ vs MAC
 *
 * ### 暗号学的ハッシュ関数（SHA-256, SHA-3等）
 * - **鍵不要**: 誰でも同じ入力から同じハッシュを計算できる
 * - **衝突耐性**: 同じハッシュを持つ2つの異なる入力を見つけることが困難
 * - **用途**: ファイルの完全性検証、デジタル署名、ブロックチェーン
 * - **公開**: ハッシュ値は公開しても安全
 *
 * ### メッセージ認証コード（SipHash等）
 * - **鍵が必要**: 秘密鍵を知っている者だけがハッシュを計算・検証できる
 * - **認証**: メッセージが改ざんされていないことを保証
 * - **用途**: データ構造の保護、通信の認証、DoS攻撃対策
 * - **秘密**: 鍵を知らない者はハッシュを計算できない
 *
 * ## SipHashの特徴
 * - 出力サイズ: 64ビット（8バイト）
 * - 鍵サイズ: 128ビット（16バイト）
 * - 構造: ARX構造（Addition, Rotation, XOR）
 * - 高速: 特に短い入力に対して極めて高速
 *
 * ## SipHash-2-4とは
 * - 2: 圧縮ラウンド数（c-rounds）
 * - 4: 最終化ラウンド数（d-rounds）
 * SipHash-1-3という高速版もありますが、SipHash-2-4が標準です。
 *
 * ## 用途
 * - **ハッシュテーブル**: ハッシュ衝突によるDoS攻撃を防ぐ
 * - **Bloomフィルタ**: 高速な集合所属判定
 * - **ネットワーク認証**: 軽量なメッセージ認証
 * - **データ構造の保護**: 悪意ある入力からの保護
 *
 * ## 注意事項
 * - SipHashは衝突耐性を保証しません（鍵を知っていれば衝突は容易）
 * - 64ビット出力は暗号学的には短い（誕生日攻撃のリスク）
 * - 用途に応じて適切なハッシュ関数を選択してください
 *
 * ## 実装
 * この実装は、siphashライブラリを使用しています。
 */

import * as SipHash from "siphash";
import { randomBytes } from "@noble/ciphers/utils.js";
import type { HashAlgorithmInfo } from "./index.js";

/**
 * SipHashの出力サイズ（ビット）
 */
export const SIPHASH_OUTPUT_SIZE = 64;

/**
 * SipHashの鍵サイズ（ビット）
 */
export const SIPHASH_KEY_SIZE = 128;

/**
 * SipHashアルゴリズムの情報
 */
export const SIPHASH_INFO: HashAlgorithmInfo = {
  name: "SipHash-2-4",
  outputSize: SIPHASH_OUTPUT_SIZE,
  // SipHashにはブロックサイズの概念がない（ストリーム処理）
  blockSize: undefined,
  description:
    "SipHashは鍵付きハッシュ関数（MAC）で、秘密鍵を使用してハッシュを計算します。ハッシュテーブルのDoS攻撃対策やメッセージ認証に使用されます。",
  keyed: true,
  keySize: SIPHASH_KEY_SIZE,
  securityLevel: "mac",
  useCase:
    "ハッシュテーブルのDoS対策、Bloomフィルタ、軽量メッセージ認証、データ構造保護",
};

/**
 * SipHashハッシュ関数（鍵付き）
 *
 * @noble/hashesライブラリを使用してSipHash-2-4ハッシュを計算します。
 *
 * @param input - ハッシュ化する入力データ
 * @param key - 128ビット（16バイト）の秘密鍵
 * @returns SipHashハッシュ値（8バイト）
 * @throws 鍵の長さが16バイトでない場合にエラーをスローします
 *
 * @example
 * ```typescript
 * const input = new TextEncoder().encode("Hello, World!");
 * const key = generateSipHashKey(); // 16バイトのランダムな鍵
 * const hash = await hashSipHash(input, key);
 * console.log(bytesToHex(hash)); // "a129ca6149be45e5" (鍵に依存)
 * ```
 */
export async function hashSipHash(
  input: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  // 鍵の長さを検証（128ビット = 16バイト）
  if (key.length !== SIPHASH_KEY_SIZE / 8) {
    throw new Error(
      `Invalid key length: expected ${SIPHASH_KEY_SIZE / 8} bytes, got ${key.length}`
    );
  }

  // siphashライブラリは鍵を4つの32ビット整数の配列として期待する
  // 16バイト鍵を4つの32ビット整数に変換（リトルエンディアン）
  const keyArray = new Uint32Array(4);
  const dataView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 4; i++) {
    keyArray[i] = dataView.getUint32(i * 4, true); // true = little-endian
  }

  // SipHash計算（戻り値は {h: number, l: number} 形式）
  const result = SipHash.hash(keyArray, input);

  // 結果を8バイトのUint8Arrayに変換（リトルエンディアン）
  const output = new Uint8Array(8);
  const outputView = new DataView(output.buffer);
  outputView.setUint32(0, result.l, true); // 下位32ビット
  outputView.setUint32(4, result.h, true); // 上位32ビット

  return Promise.resolve(output);
}

/**
 * ランダムなSipHash鍵を生成します。
 *
 * @returns 16バイト（128ビット）のランダムな鍵
 *
 * @example
 * ```typescript
 * const key = generateSipHashKey();
 * console.log(key.length); // 16
 * ```
 */
export function generateSipHashKey(): Uint8Array {
  return randomBytes(SIPHASH_KEY_SIZE / 8);
}
