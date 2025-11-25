/**
 * ハッシュ関数のサンプル実装
 *
 * このモジュールは、様々なハッシュ関数の実装を提供します。
 * ハッシュ関数は、任意の長さのデータから固定長のハッシュ値（ダイジェスト）を生成する関数です。
 *
 * ## ハッシュ関数の種類
 *
 * ### 暗号学的ハッシュ関数（Cryptographic Hash Functions）
 * - 一方向性: ハッシュ値から元のデータを復元することが計算量的に困難
 * - 衝突耐性: 同じハッシュ値を持つ2つの異なるデータを見つけることが困難
 * - 用途: ファイルの完全性検証、デジタル署名、ブロックチェーン等
 *
 * ### メッセージ認証コード（MAC: Message Authentication Code）
 * - 秘密鍵を使用して計算される鍵付きハッシュ
 * - 認証: メッセージが改ざんされていないことを保証
 * - 用途: データ構造の保護、通信の認証等
 */

// 暗号学的ハッシュ関数（鍵不要）
export type HashFunction = (input: Uint8Array) => Promise<Uint8Array>;

// 鍵付きハッシュ関数（MAC）
export type KeyedHashFunction = (input: Uint8Array, key: Uint8Array) => Promise<Uint8Array>;

/**
 * ハッシュアルゴリズムの情報
 */
export interface HashAlgorithmInfo {
  /** アルゴリズム名 */
  name: string;
  /** 出力サイズ（ビット） */
  outputSize: number;
  /** ブロックサイズ（ビット）- 内部処理の単位 */
  blockSize?: number;
  /** アルゴリズムの説明 */
  description: string;
  /** 鍵が必要かどうか */
  keyed: boolean;
  /** 鍵が必要な場合の鍵サイズ（ビット） */
  keySize?: number;
  /** セキュリティレベル */
  securityLevel: "secure" | "mac";
  /** 用途の説明 */
  useCase: string;
}

// SHA-256
export {
  SHA256_INFO,
  SHA256_OUTPUT_SIZE,
  SHA256_BLOCK_SIZE,
  hashSHA256,
} from "./sha256.js";

// SHA-512
export {
  SHA512_INFO,
  SHA512_OUTPUT_SIZE,
  SHA512_BLOCK_SIZE,
  hashSHA512,
} from "./sha512.js";

// SHA-3-256
export {
  SHA3_256_INFO,
  SHA3_256_OUTPUT_SIZE,
  SHA3_256_BLOCK_SIZE,
  hashSHA3_256,
} from "./sha3-256.js";

// BLAKE2b
export {
  BLAKE2B_INFO,
  BLAKE2B_OUTPUT_SIZE,
  BLAKE2B_BLOCK_SIZE,
  hashBLAKE2b,
} from "./blake2b.js";

// BLAKE3
export {
  BLAKE3_INFO,
  BLAKE3_OUTPUT_SIZE,
  BLAKE3_BLOCK_SIZE,
  hashBLAKE3,
} from "./blake3.js";

// SipHash
export {
  SIPHASH_INFO,
  SIPHASH_OUTPUT_SIZE,
  SIPHASH_KEY_SIZE,
  hashSipHash,
  generateSipHashKey,
} from "./siphash.js";
