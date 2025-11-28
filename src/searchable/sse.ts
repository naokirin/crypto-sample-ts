/**
 * 検索可能対称暗号（SSE: Searchable Symmetric Encryption）のサンプル実装
 *
 * 検索可能暗号は、暗号化されたデータに対して直接検索を行うことを可能にする暗号技術です。
 * この実装では、SWP（Song, Wagner, Perrig）スキームを使用します。
 *
 * ## SWPスキームの概要
 *
 * SWPスキームは、検索可能対称暗号の基本的な実装です。
 * 各キーワードに対して、HMACを使用して検索可能なタグ（インデックス）を生成します。
 * データはAESで暗号化され、キーワードと関連付けられます。
 *
 * ## セキュリティ特性
 *
 * - **機密性**: データはAESで暗号化されるため、鍵を知らない限り復号不可能
 * - **検索可能性**: キーワードから生成されたタグを使用して検索可能
 * - **制限**: サーバーは検索パターン（どのキーワードで検索されたか）を学習可能
 *
 * ## 実装の詳細
 *
 * 1. **鍵生成**: マスター鍵を生成（32バイト）
 * 2. **インデックス生成**: キーワードからHMAC-SHA256でタグを生成
 * 3. **暗号化**: データをAES-GCMで暗号化
 * 4. **検索トークン生成**: キーワードから同じタグを生成
 * 5. **検索**: タグを使用して暗号化されたインデックスを検索
 */

import { encryptAES, decryptAES, generateAESKey, AES_KEY_LENGTH } from "../symmetric/aes.js";
import { hashSHA256 } from "../hash/sha256.js";
import { randomBytes } from "@noble/ciphers/utils.js";

/**
 * SSEのマスター鍵の長さ（バイト）
 * AES-256を使用するため、32バイト（256ビット）
 */
export const SSE_MASTER_KEY_LENGTH = AES_KEY_LENGTH / 8; // 32バイト

/**
 * SSEの検索タグの長さ（バイト）
 * HMAC-SHA256の出力サイズ（32バイト）
 */
export const SSE_TAG_LENGTH = 32;

/**
 * SSEのマスター鍵
 */
export type SSEMasterKey = Uint8Array;

/**
 * SSEの暗号化されたドキュメント
 */
export interface SSEDocument {
  /** 暗号文 */
  ciphertext: Uint8Array;
  /** 認証タグ */
  authTag: Uint8Array;
  /** 初期化ベクトル（IV） */
  iv: Uint8Array;
  /** キーワードタグ（検索用インデックス） */
  keywordTags: Uint8Array[];
}

/**
 * SSEの検索結果
 */
export interface SSESearchResult {
  /** 検索に一致したドキュメント */
  documents: SSEDocument[];
  /** 検索に使用されたタグ */
  searchTag: Uint8Array;
}

/**
 * HMAC-SHA256を計算します。
 *
 * @param key - HMAC鍵
 * @param message - メッセージ
 * @returns HMAC-SHA256の結果（32バイト）
 */
async function computeHMAC(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  // Web Crypto APIを使用してHMAC-SHA256を計算
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, message);
  return new Uint8Array(signature);
}

/**
 * キーワードから検索タグを生成します。
 *
 * @param masterKey - マスター鍵
 * @param keyword - キーワード
 * @returns 検索タグ（32バイト）
 */
async function generateSearchTag(masterKey: SSEMasterKey, keyword: string): Promise<Uint8Array> {
  // キーワードをバイト配列に変換
  const keywordBytes = new TextEncoder().encode(keyword);

  // HMAC-SHA256を使用してタグを生成
  // タグ = HMAC(masterKey, keyword)
  return computeHMAC(masterKey, keywordBytes);
}

/**
 * マスター鍵からデータ暗号化用の鍵を導出します。
 *
 * @param masterKey - マスター鍵
 * @param documentId - ドキュメントID（一意の識別子）
 * @returns データ暗号化用の鍵（32バイト）
 */
async function deriveDataKey(masterKey: SSEMasterKey, documentId: Uint8Array): Promise<Uint8Array> {
  // HKDF風の鍵導出（簡易版）
  // 実際の実装では、HKDFを使用することを推奨
  const input = new Uint8Array(masterKey.length + documentId.length);
  input.set(masterKey);
  input.set(documentId, masterKey.length);

  // SHA-256でハッシュ化して鍵を導出
  return hashSHA256(input);
}

/**
 * SSEのマスター鍵を生成します。
 *
 * @returns マスター鍵（32バイト）
 */
export function generateSSEKey(): SSEMasterKey {
  return generateAESKey();
}

/**
 * ドキュメントを暗号化し、キーワードタグを生成します。
 *
 * @param masterKey - マスター鍵
 * @param documentId - ドキュメントID（一意の識別子）
 * @param plaintext - 平文
 * @param keywords - キーワードのリスト
 * @returns 暗号化されたドキュメント
 */
export async function encryptSSE(
  masterKey: SSEMasterKey,
  documentId: Uint8Array,
  plaintext: Uint8Array,
  keywords: string[]
): Promise<SSEDocument> {
  // マスター鍵の長さを検証
  if (masterKey.length !== SSE_MASTER_KEY_LENGTH) {
    throw new Error(
      `Invalid master key length: expected ${SSE_MASTER_KEY_LENGTH} bytes, got ${masterKey.length}`
    );
  }

  // データ暗号化用の鍵を導出
  const dataKey = await deriveDataKey(masterKey, documentId);

  // データをAES-GCMで暗号化
  const encryptionResult = encryptAES(plaintext, dataKey);

  // 各キーワードからタグを生成
  const keywordTags = await Promise.all(
    keywords.map((keyword) => generateSearchTag(masterKey, keyword))
  );

  return {
    ciphertext: encryptionResult.ciphertext,
    authTag: encryptionResult.authTag,
    iv: encryptionResult.iv,
    keywordTags,
  };
}

/**
 * 暗号化されたドキュメントを復号します。
 *
 * @param masterKey - マスター鍵
 * @param documentId - ドキュメントID
 * @param document - 暗号化されたドキュメント
 * @returns 復号された平文
 */
export async function decryptSSE(
  masterKey: SSEMasterKey,
  documentId: Uint8Array,
  document: SSEDocument
): Promise<Uint8Array> {
  // マスター鍵の長さを検証
  if (masterKey.length !== SSE_MASTER_KEY_LENGTH) {
    throw new Error(
      `Invalid master key length: expected ${SSE_MASTER_KEY_LENGTH} bytes, got ${masterKey.length}`
    );
  }

  // データ暗号化用の鍵を導出
  const dataKey = await deriveDataKey(masterKey, documentId);

  // データを復号
  return decryptAES(document.ciphertext, dataKey, document.iv, document.authTag);
}

/**
 * キーワードから検索トークン（タグ）を生成します。
 *
 * @param masterKey - マスター鍵
 * @param keyword - 検索キーワード
 * @returns 検索タグ（32バイト）
 */
export async function generateSearchToken(
  masterKey: SSEMasterKey,
  keyword: string
): Promise<Uint8Array> {
  // マスター鍵の長さを検証
  if (masterKey.length !== SSE_MASTER_KEY_LENGTH) {
    throw new Error(
      `Invalid master key length: expected ${SSE_MASTER_KEY_LENGTH} bytes, got ${masterKey.length}`
    );
  }

  return generateSearchTag(masterKey, keyword);
}

/**
 * 検索トークンを使用して、暗号化されたドキュメントのリストから検索を実行します。
 *
 * @param searchTag - 検索タグ（generateSearchTokenで生成）
 * @param documents - 暗号化されたドキュメントのリスト
 * @returns 検索結果
 */
export function searchSSE(searchTag: Uint8Array, documents: SSEDocument[]): SSESearchResult {
  // 検索タグの長さを検証
  if (searchTag.length !== SSE_TAG_LENGTH) {
    throw new Error(
      `Invalid search tag length: expected ${SSE_TAG_LENGTH} bytes, got ${searchTag.length}`
    );
  }

  // 検索タグと一致するドキュメントを検索
  const matchingDocuments = documents.filter((doc) =>
    doc.keywordTags.some((tag) => {
      // 定数時間比較を推奨（簡易実装のため通常の比較を使用）
      if (tag.length !== searchTag.length) {
        return false;
      }
      for (let i = 0; i < tag.length; i++) {
        if (tag[i] !== searchTag[i]) {
          return false;
        }
      }
      return true;
    })
  );

  return {
    documents: matchingDocuments,
    searchTag,
  };
}

/**
 * ドキュメントIDを生成します。
 *
 * @param length - IDの長さ（バイト）。デフォルトは16バイト
 * @returns ランダムなドキュメントID
 */
export function generateDocumentId(length = 16): Uint8Array {
  return randomBytes(length);
}
