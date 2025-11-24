import {
  type CurveType,
  type EccKeyPair,
  computeEcdh,
  generateEccKeyPair,
  signEcdsa,
  signEddsa,
  verifyEcdsa,
  verifyEddsa,
} from "../asymmetric/ecc.js";
import {
  RSA_KEY_SIZE_2048,
  type RsaKeyPair,
  decryptRSA,
  encryptRSA,
  generateRsaKeyPair,
  signRSA,
  verifyRSA,
} from "../asymmetric/rsa.js";
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

    // RSA状態
    rsaState: {
      keyPair: null as RsaKeyPair | null,
      keySize: RSA_KEY_SIZE_2048,
      mode: "encryption" as "encryption" | "signature",
      plaintext: "",
      plaintextBytes: null as Uint8Array | null,
      ciphertext: "",
      decrypted: "",
      decryptedBytes: null as Uint8Array | null,
      signatureMessage: "",
      signatureMessageBytes: null as Uint8Array | null,
      signature: "",
      verificationMessage: "",
      verificationMessageBytes: null as Uint8Array | null,
      verified: null as boolean | null,
      error: "",
      showDetails: {
        keyGeneration: true,
        encryption: true,
        decryption: true,
        signing: true,
        verification: true,
      },
    },

    // ECC状態
    eccState: {
      keyPair: null as EccKeyPair | null,
      curve: "secp256k1" as CurveType,
      mode: "signature" as "signature" | "ecdh",
      signatureMessage: "",
      signatureMessageBytes: null as Uint8Array | null,
      signature: "",
      verificationMessage: "",
      verificationMessageBytes: null as Uint8Array | null,
      verified: null as boolean | null,
      ecdhPrivateKey: "",
      ecdhPublicKey: "",
      sharedSecret: "",
      error: "",
      showDetails: {
        keyGeneration: true,
        signing: true,
        verification: true,
        ecdh: true,
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
      this.rsaState = {
        keyPair: null,
        keySize: RSA_KEY_SIZE_2048,
        mode: "encryption",
        plaintext: "",
        plaintextBytes: null,
        ciphertext: "",
        decrypted: "",
        decryptedBytes: null,
        signatureMessage: "",
        signatureMessageBytes: null,
        signature: "",
        verificationMessage: "",
        verificationMessageBytes: null,
        verified: null,
        error: "",
        showDetails: {
          keyGeneration: true,
          encryption: true,
          decryption: true,
          signing: true,
          verification: true,
        },
      };
      this.eccState = {
        keyPair: null,
        curve: "secp256k1",
        mode: "signature",
        signatureMessage: "",
        signatureMessageBytes: null,
        signature: "",
        verificationMessage: "",
        verificationMessageBytes: null,
        verified: null,
        ecdhPrivateKey: "",
        ecdhPublicKey: "",
        sharedSecret: "",
        error: "",
        showDetails: {
          keyGeneration: true,
          signing: true,
          verification: true,
          ecdh: true,
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

    /**
     * 16進数文字列をバイト配列に変換
     */
    hexToBytes(hex: string): Uint8Array {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = Number.parseInt(hex.substr(i, 2), 16);
      }
      return bytes;
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

    // ========== RSA メソッド ==========

    /**
     * RSA鍵ペアを生成
     */
    generateRsaKeyPair() {
      try {
        // keySizeを数値に変換（HTMLのselectから文字列で取得される可能性があるため）
        const keySize = Number(this.rsaState.keySize);
        this.rsaState.keyPair = generateRsaKeyPair(keySize);
        this.rsaState.error = "";
      } catch (error) {
        this.rsaState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * RSAで暗号化
     */
    encryptRSA() {
      if (!this.rsaState.keyPair || !this.rsaState.plaintext) {
        return;
      }

      try {
        const plaintextBytes = this.stringToBytes(this.rsaState.plaintext);
        this.rsaState.plaintextBytes = plaintextBytes;
        const result = encryptRSA(plaintextBytes, this.rsaState.keyPair.publicKey);
        this.rsaState.ciphertext = result.ciphertext;
        this.rsaState.error = "";
      } catch (error) {
        this.rsaState.error = `暗号化エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * RSAで復号化
     */
    decryptRSA() {
      if (!this.rsaState.keyPair || !this.rsaState.ciphertext) {
        return;
      }

      try {
        const decryptedBytes = decryptRSA(
          this.rsaState.ciphertext,
          this.rsaState.keyPair.privateKey
        );
        this.rsaState.decryptedBytes = decryptedBytes;
        this.rsaState.decrypted = this.bytesToString(decryptedBytes);
        this.rsaState.error = "";
      } catch (error) {
        this.rsaState.error = `復号化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.rsaState.decrypted = "";
        this.rsaState.decryptedBytes = null;
      }
    },

    /**
     * RSAで署名
     */
    signRSA() {
      if (!this.rsaState.keyPair || !this.rsaState.signatureMessage) {
        return;
      }

      try {
        const messageBytes = this.stringToBytes(this.rsaState.signatureMessage);
        this.rsaState.signatureMessageBytes = messageBytes;
        const result = signRSA(messageBytes, this.rsaState.keyPair.privateKey);
        this.rsaState.signature = result.signature;
        this.rsaState.error = "";
      } catch (error) {
        this.rsaState.error = `署名エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * RSAで署名を検証
     */
    verifyRSA() {
      if (
        !this.rsaState.keyPair ||
        !this.rsaState.signature ||
        !this.rsaState.verificationMessage
      ) {
        return;
      }

      try {
        const messageBytes = this.stringToBytes(this.rsaState.verificationMessage);
        this.rsaState.verificationMessageBytes = messageBytes;
        this.rsaState.verified = verifyRSA(
          messageBytes,
          this.rsaState.signature,
          this.rsaState.keyPair.publicKey
        );
        this.rsaState.error = "";
      } catch (error) {
        this.rsaState.error = `検証エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.rsaState.verified = false;
      }
    },

    // ========== ECC メソッド ==========

    /**
     * ECC鍵ペアを生成
     */
    generateEccKeyPair() {
      try {
        this.eccState.keyPair = generateEccKeyPair(this.eccState.curve);
        this.eccState.error = "";
      } catch (error) {
        this.eccState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * ECCで署名（ECDSA/EdDSA）
     */
    signECC() {
      if (!this.eccState.keyPair || !this.eccState.signatureMessage) {
        return;
      }

      try {
        const messageBytes = this.stringToBytes(this.eccState.signatureMessage);
        this.eccState.signatureMessageBytes = messageBytes;
        const curve = this.eccState.keyPair.curve;
        const result =
          curve === "ed25519" || curve === "ed448"
            ? signEddsa(messageBytes, this.eccState.keyPair.privateKey, curve)
            : signEcdsa(messageBytes, this.eccState.keyPair.privateKey, curve);
        this.eccState.signature = result.signature;
        this.eccState.error = "";
      } catch (error) {
        this.eccState.error = `署名エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * ECCで署名を検証（ECDSA/EdDSA）
     */
    verifyECC() {
      if (
        !this.eccState.keyPair ||
        !this.eccState.signature ||
        !this.eccState.verificationMessage
      ) {
        return;
      }

      try {
        const messageBytes = this.stringToBytes(this.eccState.verificationMessage);
        this.eccState.verificationMessageBytes = messageBytes;
        const curve = this.eccState.keyPair.curve;
        this.eccState.verified =
          curve === "ed25519" || curve === "ed448"
            ? verifyEddsa(
              messageBytes,
              this.eccState.signature,
              this.eccState.keyPair.publicKey,
              curve
            )
            : verifyEcdsa(
              messageBytes,
              this.eccState.signature,
              this.eccState.keyPair.publicKey,
              curve
            );
        this.eccState.error = "";
      } catch (error) {
        this.eccState.error = `検証エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.eccState.verified = false;
      }
    },

    /**
     * ECDHで共有秘密鍵を計算
     */
    computeECDH() {
      if (!this.eccState.ecdhPrivateKey || !this.eccState.ecdhPublicKey) {
        return;
      }

      try {
        const curve = this.eccState.curve;
        if (curve === "ed25519" || curve === "ed448") {
          this.eccState.error = `ECDHは${curve}ではサポートされていません`;
          return;
        }
        const result = computeEcdh(
          this.eccState.ecdhPrivateKey,
          this.eccState.ecdhPublicKey,
          curve
        );
        this.eccState.sharedSecret = result.sharedSecret;
        this.eccState.error = "";
      } catch (error) {
        this.eccState.error = `ECDH計算エラー: ${error instanceof Error ? error.message : String(error)}`;
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
