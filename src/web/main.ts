import {
  type AesEncryptionResult,
  decryptAES,
  encryptAES,
  generateAESKey,
} from "../symmetric/aes.js";
import {
  type ChaCha20EncryptionResult,
  decryptChaCha20,
  encryptChaCha20,
  generateChaCha20Key,
} from "../symmetric/chacha20.js";
import {
  computePoly1305MAC,
  generatePoly1305Key,
  verifyPoly1305MAC,
} from "../symmetric/poly1305.js";
import { bytesToHex } from "../utils/format.js";

/**
 * Alpine.jsのアプリケーション状態とメソッド
 */
function cryptoApp() {
  return {
    selectedCrypto: "",

    // AES状態
    aesState: {
      key: null as Uint8Array | null,
      plaintext: "",
      plaintextBytes: null as Uint8Array | null,
      ciphertext: null as Uint8Array | null,
      iv: null as Uint8Array | null,
      authTag: null as Uint8Array | null,
      decrypted: "",
      decryptedBytes: null as Uint8Array | null,
      error: "",
      showDetails: {
        keyGeneration: true,
        encryption: true,
        decryption: true,
      },
    },

    // ChaCha20状態
    chacha20State: {
      key: null as Uint8Array | null,
      plaintext: "",
      plaintextBytes: null as Uint8Array | null,
      ciphertext: null as Uint8Array | null,
      nonce: null as Uint8Array | null,
      authTag: null as Uint8Array | null,
      decrypted: "",
      decryptedBytes: null as Uint8Array | null,
      error: "",
      showDetails: {
        keyGeneration: true,
        encryption: true,
        decryption: true,
      },
    },

    // Poly1305状態
    poly1305State: {
      key: null as Uint8Array | null,
      message: "",
      messageBytes: null as Uint8Array | null,
      tag: null as Uint8Array | null,
      verificationMessage: "",
      verificationMessageBytes: null as Uint8Array | null,
      verified: null as boolean | null,
      error: "",
      showDetails: {
        keyGeneration: true,
        mac: true,
        verification: true,
      },
    },

    /**
     * 状態をリセット
     */
    resetState() {
      this.aesState = {
        key: null,
        plaintext: "",
        plaintextBytes: null,
        ciphertext: null,
        iv: null,
        authTag: null,
        decrypted: "",
        decryptedBytes: null,
        error: "",
        showDetails: {
          keyGeneration: true,
          encryption: true,
          decryption: true,
        },
      };
      this.chacha20State = {
        key: null,
        plaintext: "",
        plaintextBytes: null,
        ciphertext: null,
        nonce: null,
        authTag: null,
        decrypted: "",
        decryptedBytes: null,
        error: "",
        showDetails: {
          keyGeneration: true,
          encryption: true,
          decryption: true,
        },
      };
      this.poly1305State = {
        key: null,
        message: "",
        messageBytes: null,
        tag: null,
        verificationMessage: "",
        verificationMessageBytes: null,
        verified: null,
        error: "",
        showDetails: {
          keyGeneration: true,
          mac: true,
          verification: true,
        },
      };
    },

    /**
     * バイト配列を16進数文字列に変換（表示用）
     */
    formatBytes(bytes: Uint8Array | null): string {
      if (!bytes) return "";
      return bytesToHex(bytes);
    },

    /**
     * バイト配列をフォーマットされた16進数文字列に変換（読みやすく）
     */
    formatBytesReadable(bytes: Uint8Array | null): string {
      if (!bytes) return "";
      const hex = bytesToHex(bytes);
      return hex.match(/.{1,2}/g)?.join(" ") || hex;
    },

    /**
     * バイト配列をASCII文字列として表示（表示可能な文字のみ）
     */
    formatBytesAsASCII(bytes: Uint8Array | null): string {
      if (!bytes) return "";
      return Array.from(bytes)
        .map((byte) => {
          if (byte >= 32 && byte <= 126) {
            return String.fromCharCode(byte);
          }
          return ".";
        })
        .join("");
    },

    /**
     * バイト配列の詳細情報を取得
     */
    getBytesInfo(bytes: Uint8Array | null): {
      hex: string;
      hexFormatted: string;
      decimal: string;
      ascii: string;
      length: number;
    } {
      if (!bytes) {
        return {
          hex: "",
          hexFormatted: "",
          decimal: "",
          ascii: "",
          length: 0,
        };
      }
      return {
        hex: bytesToHex(bytes),
        hexFormatted: this.formatBytesReadable(bytes),
        decimal: Array.from(bytes).join(", "),
        ascii: this.formatBytesAsASCII(bytes),
        length: bytes.length,
      };
    },

    /**
     * 文字列をバイト配列に変換
     */
    stringToBytes(str: string): Uint8Array {
      return new TextEncoder().encode(str);
    },

    /**
     * バイト配列を文字列に変換
     */
    bytesToString(bytes: Uint8Array): string {
      return new TextDecoder().decode(bytes);
    },

    // ========== AES メソッド ==========

    /**
     * AES鍵を生成
     */
    generateAESKey() {
      try {
        this.aesState.key = generateAESKey();
        this.aesState.error = "";
      } catch (error) {
        this.aesState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * AESで暗号化
     */
    encryptAES() {
      if (!this.aesState.key || !this.aesState.plaintext) {
        return;
      }

      try {
        const plaintextBytes = this.stringToBytes(this.aesState.plaintext);
        this.aesState.plaintextBytes = plaintextBytes;
        const result: AesEncryptionResult = encryptAES(plaintextBytes, this.aesState.key);

        this.aesState.ciphertext = result.ciphertext;
        this.aesState.iv = result.iv;
        this.aesState.authTag = result.authTag;
        this.aesState.error = "";
      } catch (error) {
        this.aesState.error = `暗号化エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * AESで復号化
     */
    decryptAES() {
      if (
        !this.aesState.ciphertext ||
        !this.aesState.key ||
        !this.aesState.iv ||
        !this.aesState.authTag
      ) {
        return;
      }

      try {
        const decryptedBytes = decryptAES(
          this.aesState.ciphertext,
          this.aesState.key,
          this.aesState.iv,
          this.aesState.authTag
        );
        this.aesState.decryptedBytes = decryptedBytes;
        this.aesState.decrypted = this.bytesToString(decryptedBytes);
        this.aesState.error = "";
      } catch (error) {
        this.aesState.error = `復号化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.aesState.decrypted = "";
        this.aesState.decryptedBytes = null;
      }
    },

    // ========== ChaCha20 メソッド ==========

    /**
     * ChaCha20鍵を生成
     */
    generateChaCha20Key() {
      try {
        this.chacha20State.key = generateChaCha20Key();
        this.chacha20State.error = "";
      } catch (error) {
        this.chacha20State.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * ChaCha20で暗号化
     */
    encryptChaCha20() {
      if (!this.chacha20State.key || !this.chacha20State.plaintext) {
        return;
      }

      try {
        const plaintextBytes = this.stringToBytes(this.chacha20State.plaintext);
        this.chacha20State.plaintextBytes = plaintextBytes;
        const result: ChaCha20EncryptionResult = encryptChaCha20(
          plaintextBytes,
          this.chacha20State.key
        );

        this.chacha20State.ciphertext = result.ciphertext;
        this.chacha20State.nonce = result.nonce;
        this.chacha20State.authTag = result.authTag;
        this.chacha20State.error = "";
      } catch (error) {
        this.chacha20State.error = `暗号化エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * ChaCha20で復号化
     */
    decryptChaCha20() {
      if (
        !this.chacha20State.ciphertext ||
        !this.chacha20State.key ||
        !this.chacha20State.nonce ||
        !this.chacha20State.authTag
      ) {
        return;
      }

      try {
        const decryptedBytes = decryptChaCha20(
          this.chacha20State.ciphertext,
          this.chacha20State.key,
          this.chacha20State.nonce,
          this.chacha20State.authTag
        );
        this.chacha20State.decryptedBytes = decryptedBytes;
        this.chacha20State.decrypted = this.bytesToString(decryptedBytes);
        this.chacha20State.error = "";
      } catch (error) {
        this.chacha20State.error = `復号化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.chacha20State.decrypted = "";
        this.chacha20State.decryptedBytes = null;
      }
    },

    // ========== Poly1305 メソッド ==========

    /**
     * Poly1305鍵を生成
     */
    generatePoly1305Key() {
      try {
        this.poly1305State.key = generatePoly1305Key();
        this.poly1305State.error = "";
      } catch (error) {
        this.poly1305State.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Poly1305でMACを計算
     */
    computePoly1305MAC() {
      if (!this.poly1305State.key || !this.poly1305State.message) {
        return;
      }

      try {
        const messageBytes = this.stringToBytes(this.poly1305State.message);
        this.poly1305State.messageBytes = messageBytes;
        this.poly1305State.tag = computePoly1305MAC(messageBytes, this.poly1305State.key);
        this.poly1305State.error = "";
      } catch (error) {
        this.poly1305State.error = `MAC計算エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Poly1305でMACを検証
     */
    verifyPoly1305MAC() {
      if (
        !this.poly1305State.key ||
        !this.poly1305State.tag ||
        !this.poly1305State.verificationMessage
      ) {
        return;
      }

      try {
        const verificationMessageBytes = this.stringToBytes(this.poly1305State.verificationMessage);
        this.poly1305State.verificationMessageBytes = verificationMessageBytes;
        this.poly1305State.verified = verifyPoly1305MAC(
          verificationMessageBytes,
          this.poly1305State.key,
          this.poly1305State.tag
        );
        this.poly1305State.error = "";
      } catch (error) {
        this.poly1305State.error = `MAC検証エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.poly1305State.verified = false;
      }
    },
  };
}

// Alpine.jsのグローバルスコープに登録
declare global {
  interface Window {
    cryptoApp: typeof cryptoApp;
  }
}

// グローバルスコープに登録（Alpine.jsからアクセス可能にする）
declare const window: Window & typeof globalThis;
if (typeof window !== "undefined") {
  window.cryptoApp = cryptoApp;
}
