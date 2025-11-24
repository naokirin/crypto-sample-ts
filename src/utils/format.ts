/**
 * バイト配列を表示用の文字列に変換するユーティリティ関数
 */

/**
 * バイト配列を16進数文字列に変換します。
 *
 * @param bytes - 変換するバイト配列
 * @returns 16進数文字列（例: "48656c6c6f"）
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * 16進数文字列をバイト配列に変換します。
 *
 * @param hex - 16進数文字列（例: "48656c6c6f"）
 * @returns バイト配列
 * @throws 無効な16進数文字列の場合にエラーをスローします。
 */
export function hexToBytes(hex: string): Uint8Array {
  // 空白を削除
  const cleanHex = hex.replace(/\s+/g, "");
  // 長さが偶数の場合のみ処理
  if (cleanHex.length % 2 !== 0) {
    throw new Error("Invalid hex string: length must be even");
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.substring(i, i + 2), 16);
    if (isNaN(byte)) {
      throw new Error(`Invalid hex string: invalid character at position ${i}`);
    }
    bytes[i / 2] = byte;
  }
  return bytes;
}

/**
 * バイト配列をBase64文字列に変換します。
 *
 * @param bytes - 変換するバイト配列
 * @returns Base64文字列
 */
export function bytesToBase64(bytes: Uint8Array): string {
  // Node.js環境ではBufferを使用、ブラウザ環境ではbtoaを使用
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  // ブラウザ環境
  const binary = Array.from(bytes)
    .map((byte) => String.fromCharCode(byte))
    .join("");
  return btoa(binary);
}

/**
 * Base64文字列をバイト配列に変換します。
 *
 * @param base64 - Base64文字列
 * @returns バイト配列
 */
export function base64ToBytes(base64: string): Uint8Array {
  // Node.js環境ではBufferを使用、ブラウザ環境ではatobを使用
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }
  // ブラウザ環境
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * バイト配列を表示用の16進数文字列に変換します（読みやすくするためにスペースを挿入）。
 *
 * @param bytes - 変換するバイト配列
 * @param bytesPerLine - 1行あたりのバイト数（デフォルト: 16）
 * @returns フォーマットされた16進数文字列
 */
export function bytesToHexFormatted(bytes: Uint8Array, bytesPerLine: number = 16): string {
  const hex = bytesToHex(bytes);
  const lines: string[] = [];
  for (let i = 0; i < hex.length; i += bytesPerLine * 2) {
    const line = hex.slice(i, i + bytesPerLine * 2);
    const formatted = line.match(/.{1,2}/g)?.join(" ") || "";
    lines.push(formatted);
  }
  return lines.join("\n");
}

