import {
  type ABEMasterKey,
  type ABEPrivateKey,
  type ABEPublicParams,
  decryptABE,
  decryptKPABE,
  encryptABE,
  encryptKPABE,
  extractABEKey,
  extractKPABEKey,
  generateABEKeyPair,
  generateKPABEKeyPair,
  initABE,
} from "../asymmetric/abe.js";
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
  type IBEMasterKey,
  type IBEPrivateKey,
  type IBEPublicParams,
  decryptIBE,
  encryptIBE,
  extractIBEKey,
  generateIBEKeyPair,
  initIBE,
} from "../asymmetric/ibe.js";
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
import {
  generateSipHashKey,
  hashBLAKE2b,
  hashBLAKE3,
  hashSHA256,
  hashSHA3_256,
  hashSHA512,
  hashSipHash,
} from "../hash/index.js";
import {
  decapsulateKyber,
  encapsulateKyber,
  generateKyberKeyPair,
  initKyber,
} from "../post-quantum/kyber.js";
import {
  generateDilithiumKeyPair,
  initDilithium,
  signDilithium,
  verifyDilithium,
} from "../post-quantum/dilithium.js";
import {
  generateFalconKeyPair,
  initFalcon,
  signFalcon,
  verifyFalcon,
} from "../post-quantum/falcon.js";
import {
  type SSEDocument,
  type SSEMasterKey,
  decryptSSE,
  encryptSSE,
  generateDocumentId,
  generateSearchToken,
  generateSSEKey,
  searchSSE,
} from "../searchable/sse.js";
import { bytesToHex } from "../utils/format.js";

/**
 * ハッシュアルゴリズムの型定義
 */
type HashAlgorithm = "sha256" | "sha512" | "sha3-256" | "blake2b" | "blake3" | "siphash";

/**
 * URLのクエリパラメータから暗号技術を取得
 */
function getCryptoFromQuery(): string {
  // ブラウザ環境でのみ動作するため、型アサーションを使用
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const global = globalThis as any;
  if (!global || !global.location || !global.location.search) {
    return "";
  }
  const params = new URLSearchParams(global.location.search);
  const crypto = params.get("crypto");
  return crypto || "";
}

/**
 * Alpine.jsのアプリケーション状態とメソッド
 */
function cryptoApp() {
  return {
    selectedCrypto: getCryptoFromQuery(),

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

    // IBE状態
    ibeState: {
      initialized: false,
      masterKey: null as IBEMasterKey | null,
      publicParams: null as IBEPublicParams | null,
      identity: "",
      privateKey: null as IBEPrivateKey | null,
      plaintext: "",
      plaintextBytes: null as Uint8Array | null,
      ciphertext: null as Uint8Array | null,
      decrypted: "",
      decryptedBytes: null as Uint8Array | null,
      error: "",
      showDetails: {
        initialization: true,
        keyGeneration: true,
        keyExtraction: true,
        encryption: true,
        decryption: true,
      },
    },

    // ABE状態
    abeState: {
      initialized: false,
      masterKey: null as ABEMasterKey | null,
      publicParams: null as ABEPublicParams | null,
      attributes: [] as string[],
      attributeInput: "",
      privateKey: null as ABEPrivateKey | null,
      policy: "",
      plaintext: "",
      plaintextBytes: null as Uint8Array | null,
      ciphertext: null as Uint8Array | null,
      decrypted: "",
      decryptedBytes: null as Uint8Array | null,
      decryptionSucceeded: null as boolean | null,
      error: "",
      showDetails: {
        initialization: true,
        keyGeneration: true,
        keyExtraction: true,
        encryption: true,
        decryption: true,
      },
    },

    // KP-ABE状態
    kpabeState: {
      initialized: false,
      masterKey: null as ABEMasterKey | null,
      publicParams: null as ABEPublicParams | null,
      policy: "",
      privateKey: null as ABEPrivateKey | null,
      attributes: [] as string[],
      attributeInput: "",
      plaintext: "",
      plaintextBytes: null as Uint8Array | null,
      ciphertext: null as Uint8Array | null,
      decrypted: "",
      decryptedBytes: null as Uint8Array | null,
      decryptionSucceeded: null as boolean | null,
      error: "",
      showDetails: {
        initialization: true,
        keyGeneration: true,
        keyExtraction: true,
        encryption: true,
        decryption: true,
      },
    },

    // Hash状態
    hashState: {
      selectedAlgorithm: "sha256" as HashAlgorithm,
      inputText: "",
      inputBytes: null as Uint8Array | null,
      hash: null as Uint8Array | null,
      processingTime: 0,
      error: "",
      // SipHash用の鍵
      siphashKey: null as Uint8Array | null,
      showDetails: {
        input: true,
        processing: true,
        output: true,
      },
      // 比較モード
      comparisonMode: false,
      comparisonResults: {} as Record<string, { hash: string; time: number }>,
    },

    // Kyber状態
    kyberState: {
      initialized: false,
      publicKey: null as Uint8Array | null,
      privateKey: null as Uint8Array | null,
      ciphertext: null as Uint8Array | null,
      sharedSecret: null as Uint8Array | null,
      decapsulatedSecret: null as Uint8Array | null,
      error: "",
      showDetails: {
        initialization: true,
        keyGeneration: true,
        encapsulation: true,
        decapsulation: true,
      },
    },

    // Dilithium状態
    dilithiumState: {
      initialized: false,
      publicKey: null as Uint8Array | null,
      privateKey: null as Uint8Array | null,
      message: "",
      messageBytes: null as Uint8Array | null,
      signature: null as Uint8Array | null,
      verificationMessage: "",
      verificationMessageBytes: null as Uint8Array | null,
      verified: null as boolean | null,
      error: "",
      showDetails: {
        initialization: true,
        keyGeneration: true,
        signing: true,
        verification: true,
      },
    },

    // FALCON状態
    falconState: {
      initialized: false,
      publicKey: null as Uint8Array | null,
      privateKey: null as Uint8Array | null,
      message: "",
      messageBytes: null as Uint8Array | null,
      signature: null as Uint8Array | null,
      verificationMessage: "",
      verificationMessageBytes: null as Uint8Array | null,
      verified: null as boolean | null,
      error: "",
      showDetails: {
        initialization: true,
        keyGeneration: true,
        signing: true,
        verification: true,
      },
    },

    // SSE状態
    sseState: {
      masterKey: null as SSEMasterKey | null,
      documents: [] as Array<{ id: Uint8Array; document: SSEDocument }>,
      documentId: null as Uint8Array | null,
      plaintext: "",
      plaintextBytes: null as Uint8Array | null,
      keywords: [] as string[],
      keywordInput: "",
      encryptedDocument: null as SSEDocument | null,
      searchKeyword: "",
      searchTag: null as Uint8Array | null,
      searchResults: [] as Array<{ id: Uint8Array; document: SSEDocument }>,
      selectedDocumentId: null as Uint8Array | null,
      decrypted: "",
      decryptedBytes: null as Uint8Array | null,
      error: "",
      showDetails: {
        keyGeneration: true,
        encryption: true,
        search: true,
        decryption: true,
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
      this.ibeState = {
        initialized: false,
        masterKey: null,
        publicParams: null,
        identity: "",
        privateKey: null,
        plaintext: "",
        plaintextBytes: null,
        ciphertext: null,
        decrypted: "",
        decryptedBytes: null,
        error: "",
        showDetails: {
          initialization: true,
          keyGeneration: true,
          keyExtraction: true,
          encryption: true,
          decryption: true,
        },
      };
      this.abeState = {
        initialized: false,
        masterKey: null,
        publicParams: null,
        attributes: [],
        attributeInput: "",
        privateKey: null,
        policy: "",
        plaintext: "",
        plaintextBytes: null,
        ciphertext: null,
        decrypted: "",
        decryptedBytes: null,
        decryptionSucceeded: null,
        error: "",
        showDetails: {
          initialization: true,
          keyGeneration: true,
          keyExtraction: true,
          encryption: true,
          decryption: true,
        },
      };
      this.kpabeState = {
        initialized: false,
        masterKey: null,
        publicParams: null,
        policy: "",
        privateKey: null,
        attributes: [],
        attributeInput: "",
        plaintext: "",
        plaintextBytes: null,
        ciphertext: null,
        decrypted: "",
        decryptedBytes: null,
        decryptionSucceeded: null,
        error: "",
        showDetails: {
          initialization: true,
          keyGeneration: true,
          keyExtraction: true,
          encryption: true,
          decryption: true,
        },
      };
      // selectedCryptoに基づいて適切なアルゴリズムを設定
      let selectedAlgorithm: HashAlgorithm = "sha256";
      let comparisonMode = false;

      if (this.selectedCrypto === "hash-sha256") {
        selectedAlgorithm = "sha256";
      } else if (this.selectedCrypto === "hash-sha512") {
        selectedAlgorithm = "sha512";
      } else if (this.selectedCrypto === "hash-sha3-256") {
        selectedAlgorithm = "sha3-256";
      } else if (this.selectedCrypto === "hash-blake2b") {
        selectedAlgorithm = "blake2b";
      } else if (this.selectedCrypto === "hash-blake3") {
        selectedAlgorithm = "blake3";
      } else if (this.selectedCrypto === "hash-compare") {
        comparisonMode = true;
      } else if (this.selectedCrypto === "siphash") {
        selectedAlgorithm = "siphash";
      }

      this.hashState = {
        selectedAlgorithm: selectedAlgorithm,
        inputText: "",
        inputBytes: null,
        hash: null,
        processingTime: 0,
        error: "",
        siphashKey: null,
        showDetails: {
          input: true,
          processing: true,
          output: true,
        },
        comparisonMode: comparisonMode,
        comparisonResults: {},
      };
      this.kyberState = {
        initialized: false,
        publicKey: null,
        privateKey: null,
        ciphertext: null,
        sharedSecret: null,
        decapsulatedSecret: null,
        error: "",
        showDetails: {
          initialization: true,
          keyGeneration: true,
          encapsulation: true,
          decapsulation: true,
        },
      };
      this.sseState = {
        masterKey: null,
        documents: [],
        documentId: null,
        plaintext: "",
        plaintextBytes: null,
        keywords: [],
        keywordInput: "",
        encryptedDocument: null,
        searchKeyword: "",
        searchTag: null,
        searchResults: [],
        selectedDocumentId: null,
        decrypted: "",
        decryptedBytes: null,
        error: "",
        showDetails: {
          keyGeneration: true,
          encryption: true,
          search: true,
          decryption: true,
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

    // ========== IBE メソッド ==========

    /**
     * IBEを初期化
     */
    async initializeIBE() {
      try {
        this.ibeState.error = "";
        await initIBE();
        this.ibeState.initialized = true;
      } catch (error) {
        this.ibeState.error = `初期化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.ibeState.initialized = false;
      }
    },

    /**
     * IBEマスター鍵ペアを生成
     */
    async generateIBEKeyPair() {
      if (!this.ibeState.initialized) {
        await this.initializeIBE();
      }

      try {
        const result = await generateIBEKeyPair();
        this.ibeState.masterKey = result.masterKey;
        this.ibeState.publicParams = result.publicParams;
        this.ibeState.error = "";
      } catch (error) {
        this.ibeState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * IBE秘密鍵を抽出
     */
    async extractIBEKey() {
      if (!this.ibeState.masterKey || !this.ibeState.identity) {
        this.ibeState.error = "マスター鍵とアイデンティティが必要です";
        return;
      }

      try {
        this.ibeState.privateKey = await extractIBEKey(
          this.ibeState.masterKey,
          this.ibeState.identity
        );
        this.ibeState.error = "";
      } catch (error) {
        this.ibeState.error = `鍵抽出エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.ibeState.privateKey = null;
      }
    },

    /**
     * IBEで暗号化
     */
    async encryptIBE() {
      if (!this.ibeState.publicParams || !this.ibeState.identity || !this.ibeState.plaintext) {
        return;
      }

      try {
        const plaintextBytes = this.stringToBytes(this.ibeState.plaintext);
        this.ibeState.plaintextBytes = plaintextBytes;
        this.ibeState.ciphertext = await encryptIBE(
          this.ibeState.publicParams,
          this.ibeState.identity,
          plaintextBytes
        );
        this.ibeState.error = "";
      } catch (error) {
        this.ibeState.error = `暗号化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.ibeState.ciphertext = null;
      }
    },

    /**
     * IBEで復号化
     */
    async decryptIBE() {
      if (!this.ibeState.privateKey || !this.ibeState.ciphertext) {
        return;
      }

      try {
        const decryptedBytes = await decryptIBE(this.ibeState.privateKey, this.ibeState.ciphertext);
        this.ibeState.decryptedBytes = decryptedBytes;
        this.ibeState.decrypted = this.bytesToString(decryptedBytes);
        this.ibeState.error = "";
      } catch (error) {
        this.ibeState.error = `復号化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.ibeState.decrypted = "";
        this.ibeState.decryptedBytes = null;
      }
    },

    /**
     * ABEを初期化
     */
    async initializeABE() {
      if (this.abeState.initialized) {
        return;
      }

      try {
        this.abeState.error = "";
        await initABE();
        this.abeState.initialized = true;
      } catch (error) {
        this.abeState.error = `初期化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.abeState.initialized = false;
      }
    },

    /**
     * ABEマスター鍵ペアを生成
     */
    async generateABEKeyPair() {
      if (!this.abeState.initialized) {
        await this.initializeABE();
      }

      try {
        const result = await generateABEKeyPair();
        this.abeState.masterKey = result.masterKey;
        this.abeState.publicParams = result.publicParams;
        this.abeState.error = "";
      } catch (error) {
        this.abeState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * ABE秘密鍵を抽出
     */
    async extractABEKey() {
      if (!this.abeState.masterKey || !this.abeState.attributes.length) {
        this.abeState.error = "マスター鍵と属性が必要です";
        return;
      }

      try {
        this.abeState.privateKey = await extractABEKey(
          this.abeState.masterKey,
          this.abeState.attributes
        );
        this.abeState.error = "";
      } catch (error) {
        this.abeState.error = `鍵抽出エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.abeState.privateKey = null;
      }
    },

    /**
     * 属性を追加
     * カンマ区切りの入力もサポート（例: "A, B, C"）
     */
    addAttribute() {
      const input = this.abeState.attributeInput.trim();
      if (!input) {
        return;
      }

      // カンマ区切りで分割し、各属性を追加
      const attributes = input
        .split(",")
        .map((attr) => attr.trim())
        .filter((attr) => attr.length > 0);

      // 重複をチェックして追加
      for (const attr of attributes) {
        if (!this.abeState.attributes.includes(attr)) {
          this.abeState.attributes.push(attr);
        }
      }

      this.abeState.attributeInput = "";
    },

    /**
     * 属性を削除
     */
    removeAttribute(index: number) {
      this.abeState.attributes.splice(index, 1);
    },

    /**
     * ABEで暗号化
     */
    async encryptABE() {
      if (!this.abeState.publicParams || !this.abeState.policy || !this.abeState.plaintext) {
        return;
      }

      try {
        const plaintextBytes = this.stringToBytes(this.abeState.plaintext);
        this.abeState.plaintextBytes = plaintextBytes;
        this.abeState.ciphertext = await encryptABE(
          this.abeState.publicParams,
          this.abeState.policy,
          plaintextBytes
        );
        this.abeState.error = "";
      } catch (error) {
        this.abeState.error = `暗号化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.abeState.ciphertext = null;
      }
    },

    /**
     * ABEで復号化
     */
    async decryptABE() {
      if (!this.abeState.privateKey || !this.abeState.ciphertext) {
        return;
      }

      try {
        const decryptedBytes = await decryptABE(this.abeState.privateKey, this.abeState.ciphertext);
        this.abeState.decryptedBytes = decryptedBytes;
        this.abeState.decrypted = this.bytesToString(decryptedBytes);
        this.abeState.decryptionSucceeded = true;
        this.abeState.error = "";
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // 属性不一致のエラーを検出
        if (
          errorMessage.includes("Attribute mismatch") ||
          errorMessage.includes("属性が一致しません")
        ) {
          this.abeState.decryptionSucceeded = false;
          this.abeState.error = "";
        } else {
          // その他のエラーは通常のエラーとして表示
          this.abeState.error = `復号化エラー: ${errorMessage}`;
          this.abeState.decryptionSucceeded = null;
        }

        this.abeState.decrypted = "";
        this.abeState.decryptedBytes = null;
      }
    },

    /**
     * KP-ABEを初期化
     */
    async initializeKPABE() {
      if (this.kpabeState.initialized) {
        return;
      }

      try {
        this.kpabeState.error = "";
        await initABE();
        this.kpabeState.initialized = true;
      } catch (error) {
        this.kpabeState.error = `初期化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.kpabeState.initialized = false;
      }
    },

    /**
     * KP-ABEマスター鍵ペアを生成
     */
    async generateKPABEKeyPair() {
      if (!this.kpabeState.initialized) {
        await this.initializeKPABE();
      }

      try {
        this.kpabeState.error = "";
        const result = await generateKPABEKeyPair();
        
        if (!result || !result.masterKey || !result.publicParams) {
          throw new Error("Invalid key pair result");
        }
        
        this.kpabeState.masterKey = result.masterKey;
        this.kpabeState.publicParams = result.publicParams;
        this.kpabeState.error = "";
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.kpabeState.error = `鍵生成エラー: ${errorMessage}`;
        console.error("KP-ABE key pair generation error:", error);
        this.kpabeState.masterKey = null;
        this.kpabeState.publicParams = null;
      }
    },

    /**
     * KP-ABE秘密鍵を抽出（ポリシーから）
     */
    async extractKPABEKey() {
      if (!this.kpabeState.masterKey || !this.kpabeState.policy) {
        this.kpabeState.error = "マスター鍵とポリシーが必要です";
        return;
      }

      try {
        this.kpabeState.privateKey = await extractKPABEKey(
          this.kpabeState.masterKey,
          this.kpabeState.policy
        );
        this.kpabeState.error = "";
      } catch (error) {
        this.kpabeState.error = `鍵抽出エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.kpabeState.privateKey = null;
      }
    },

    /**
     * KP-ABEで属性を追加
     */
    addKPABEAttribute() {
      const input = this.kpabeState.attributeInput.trim();
      if (!input) {
        return;
      }

      // カンマ区切りで分割し、各属性を追加
      const attributes = input
        .split(",")
        .map((attr) => attr.trim())
        .filter((attr) => attr.length > 0);

      // 重複をチェックして追加
      for (const attr of attributes) {
        if (!this.kpabeState.attributes.includes(attr)) {
          this.kpabeState.attributes.push(attr);
        }
      }

      this.kpabeState.attributeInput = "";
    },

    /**
     * KP-ABEで属性を削除
     */
    removeKPABEAttribute(index: number) {
      this.kpabeState.attributes.splice(index, 1);
    },

    /**
     * KP-ABEで暗号化（属性セットから）
     */
    async encryptKPABE() {
      if (!this.kpabeState.publicParams || !this.kpabeState.attributes.length || !this.kpabeState.plaintext) {
        return;
      }

      try {
        const plaintextBytes = this.stringToBytes(this.kpabeState.plaintext);
        this.kpabeState.plaintextBytes = plaintextBytes;
        this.kpabeState.ciphertext = await encryptKPABE(
          this.kpabeState.publicParams,
          this.kpabeState.attributes,
          plaintextBytes
        );
        this.kpabeState.error = "";
      } catch (error) {
        this.kpabeState.error = `暗号化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.kpabeState.ciphertext = null;
      }
    },

    /**
     * KP-ABEで復号化
     */
    async decryptKPABE() {
      if (!this.kpabeState.privateKey || !this.kpabeState.ciphertext) {
        return;
      }

      try {
        const decryptedBytes = await decryptKPABE(this.kpabeState.privateKey, this.kpabeState.ciphertext);
        this.kpabeState.decryptedBytes = decryptedBytes;
        this.kpabeState.decrypted = this.bytesToString(decryptedBytes);
        this.kpabeState.decryptionSucceeded = true;
        this.kpabeState.error = "";
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // 属性不一致のエラーを検出
        if (
          errorMessage.includes("Attribute mismatch") ||
          errorMessage.includes("属性が一致しません")
        ) {
          this.kpabeState.decryptionSucceeded = false;
          this.kpabeState.error = "";
        } else {
          // その他のエラーは通常のエラーとして表示
          this.kpabeState.error = `復号化エラー: ${errorMessage}`;
          this.kpabeState.decryptionSucceeded = null;
        }

        this.kpabeState.decrypted = "";
        this.kpabeState.decryptedBytes = null;
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

    /**
     * SipHash用の鍵を生成
     */
    generateSipHashKey() {
      try {
        this.hashState.siphashKey = generateSipHashKey();
        this.hashState.error = "";
      } catch (error) {
        this.hashState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * ハッシュ計算
     */
    async computeHash() {
      if (!this.hashState.inputText) {
        this.hashState.error = "入力テキストを入力してください";
        return;
      }

      try {
        const startTime = performance.now();
        const inputBytes = new TextEncoder().encode(this.hashState.inputText);
        this.hashState.inputBytes = inputBytes;

        let hash: Uint8Array;

        switch (this.hashState.selectedAlgorithm) {
          case "sha256":
            hash = await hashSHA256(inputBytes);
            break;
          case "sha512":
            hash = await hashSHA512(inputBytes);
            break;
          case "sha3-256":
            hash = await hashSHA3_256(inputBytes);
            break;
          case "blake2b":
            hash = await hashBLAKE2b(inputBytes);
            break;
          case "blake3":
            hash = await hashBLAKE3(inputBytes);
            break;
          case "siphash":
            if (!this.hashState.siphashKey) {
              this.hashState.error = "SipHashには鍵が必要です。鍵を生成してください。";
              return;
            }
            hash = await hashSipHash(inputBytes, this.hashState.siphashKey);
            break;
          default:
            this.hashState.error = "未知のアルゴリズムです";
            return;
        }

        this.hashState.hash = hash;
        this.hashState.processingTime = performance.now() - startTime;
        this.hashState.error = "";
      } catch (error) {
        this.hashState.error = `ハッシュ計算エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * すべてのハッシュアルゴリズムで比較
     */
    async compareAllHashes() {
      if (!this.hashState.inputText) {
        this.hashState.error = "入力テキストを入力してください";
        return;
      }

      try {
        const inputBytes = new TextEncoder().encode(this.hashState.inputText);
        this.hashState.inputBytes = inputBytes;
        this.hashState.comparisonResults = {};

        // 暗号学的ハッシュ関数
        const algorithms = [
          { name: "SHA-256", fn: hashSHA256 },
          { name: "SHA-512", fn: hashSHA512 },
          { name: "SHA-3-256", fn: hashSHA3_256 },
          { name: "BLAKE2b", fn: hashBLAKE2b },
          { name: "BLAKE3", fn: hashBLAKE3 },
        ];

        for (const algo of algorithms) {
          const startTime = performance.now();
          const hash = await algo.fn(inputBytes);
          const time = performance.now() - startTime;
          this.hashState.comparisonResults[algo.name] = {
            hash: bytesToHex(hash),
            time: time,
          };
        }

        // SipHashは鍵が必要なので別処理
        if (this.hashState.siphashKey) {
          const startTime = performance.now();
          const hash = await hashSipHash(inputBytes, this.hashState.siphashKey);
          const time = performance.now() - startTime;
          this.hashState.comparisonResults["SipHash-2-4"] = {
            hash: bytesToHex(hash),
            time: time,
          };
        }

        this.hashState.error = "";
      } catch (error) {
        this.hashState.error = `比較エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Kyber初期化
     */
    async initKyber() {
      try {
        this.kyberState.error = "";
        await initKyber();
        this.kyberState.initialized = true;
      } catch (error) {
        this.kyberState.error = `初期化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.kyberState.initialized = false;
      }
    },

    /**
     * Kyber鍵ペア生成
     */
    async generateKyberKeyPair() {
      if (!this.kyberState.initialized) {
        await this.initKyber();
      }

      try {
        this.kyberState.error = "";
        const keyPair = await generateKyberKeyPair();
        this.kyberState.publicKey = keyPair.publicKey;
        this.kyberState.privateKey = keyPair.privateKey;
      } catch (error) {
        this.kyberState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Kyberカプセル化
     */
    async encapsulateKyber() {
      if (!this.kyberState.publicKey) {
        this.kyberState.error = "まず鍵ペアを生成してください";
        return;
      }

      try {
        this.kyberState.error = "";
        const result = await encapsulateKyber(this.kyberState.publicKey);
        this.kyberState.ciphertext = result.ciphertext;
        this.kyberState.sharedSecret = result.sharedSecret;
      } catch (error) {
        this.kyberState.error = `カプセル化エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Kyberデカプセル化
     */
    async decapsulateKyber() {
      if (
        !this.kyberState.ciphertext ||
        !this.kyberState.privateKey ||
        !this.kyberState.publicKey
      ) {
        this.kyberState.error = "カプセル化を実行してからデカプセル化してください";
        return;
      }

      try {
        this.kyberState.error = "";
        const decapsulatedSecret = await decapsulateKyber(
          this.kyberState.ciphertext,
          this.kyberState.privateKey,
          this.kyberState.publicKey
        );
        this.kyberState.decapsulatedSecret = decapsulatedSecret;
      } catch (error) {
        this.kyberState.error = `デカプセル化エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Dilithium初期化
     */
    async initDilithium() {
      try {
        this.dilithiumState.error = "";
        await initDilithium();
        this.dilithiumState.initialized = true;
      } catch (error) {
        this.dilithiumState.error = `初期化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.dilithiumState.initialized = false;
      }
    },

    /**
     * Dilithium鍵ペア生成
     */
    async generateDilithiumKeyPair() {
      if (!this.dilithiumState.initialized) {
        await this.initDilithium();
      }

      try {
        this.dilithiumState.error = "";
        const keyPair = await generateDilithiumKeyPair();
        this.dilithiumState.publicKey = keyPair.publicKey;
        this.dilithiumState.privateKey = keyPair.privateKey;
      } catch (error) {
        this.dilithiumState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Dilithium署名
     */
    async signDilithium() {
      if (!this.dilithiumState.privateKey) {
        this.dilithiumState.error = "まず鍵ペアを生成してください";
        return;
      }

      if (!this.dilithiumState.message) {
        this.dilithiumState.error = "メッセージを入力してください";
        return;
      }

      try {
        this.dilithiumState.error = "";
        const messageBytes = new TextEncoder().encode(this.dilithiumState.message);
        this.dilithiumState.messageBytes = messageBytes;
        const signature = await signDilithium(messageBytes, this.dilithiumState.privateKey);
        this.dilithiumState.signature = signature;
      } catch (error) {
        this.dilithiumState.error = `署名エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * Dilithium署名検証
     */
    async verifyDilithium() {
      if (!this.dilithiumState.signature || !this.dilithiumState.publicKey) {
        this.dilithiumState.error = "署名を生成してから検証してください";
        return;
      }

      if (!this.dilithiumState.verificationMessage) {
        this.dilithiumState.error = "検証するメッセージを入力してください";
        return;
      }

      try {
        this.dilithiumState.error = "";
        const messageBytes = new TextEncoder().encode(this.dilithiumState.verificationMessage);
        this.dilithiumState.verificationMessageBytes = messageBytes;
        const isValid = await verifyDilithium(
          messageBytes,
          this.dilithiumState.signature,
          this.dilithiumState.publicKey
        );
        this.dilithiumState.verified = isValid;
      } catch (error) {
        this.dilithiumState.error = `検証エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * FALCON初期化
     */
    async initFalcon() {
      try {
        this.falconState.error = "";
        await initFalcon();
        this.falconState.initialized = true;
      } catch (error) {
        this.falconState.error = `初期化エラー: ${error instanceof Error ? error.message : String(error)}`;
        this.falconState.initialized = false;
      }
    },

    /**
     * FALCON鍵ペア生成
     */
    async generateFalconKeyPair() {
      if (!this.falconState.initialized) {
        await this.initFalcon();
      }
      try {
        this.falconState.error = "";
        const keyPair = await generateFalconKeyPair();
        this.falconState.publicKey = keyPair.publicKey;
        this.falconState.privateKey = keyPair.privateKey;
      } catch (error) {
        this.falconState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * FALCON署名
     */
    async signFalcon() {
      if (!this.falconState.privateKey) {
        this.falconState.error = "まず鍵ペアを生成してください";
        return;
      }

      if (!this.falconState.message) {
        this.falconState.error = "メッセージを入力してください";
        return;
      }

      try {
        this.falconState.error = "";
        const messageBytes = new TextEncoder().encode(this.falconState.message);
        this.falconState.messageBytes = messageBytes;
        const signature = await signFalcon(messageBytes, this.falconState.privateKey);
        this.falconState.signature = signature;
      } catch (error) {
        this.falconState.error = `署名エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * FALCON署名検証
     */
    async verifyFalcon() {
      if (!this.falconState.signature || !this.falconState.publicKey) {
        this.falconState.error = "署名を生成してから検証してください";
        return;
      }

      if (!this.falconState.verificationMessage) {
        this.falconState.error = "検証するメッセージを入力してください";
        return;
      }

      try {
        this.falconState.error = "";
        const messageBytes = new TextEncoder().encode(this.falconState.verificationMessage);
        this.falconState.verificationMessageBytes = messageBytes;
        const isValid = await verifyFalcon(
          messageBytes,
          this.falconState.signature,
          this.falconState.publicKey
        );
        this.falconState.verified = isValid;
      } catch (error) {
        this.falconState.error = `検証エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * SSEマスター鍵生成
     */
    generateSSEKey() {
      try {
        this.sseState.masterKey = generateSSEKey();
        this.sseState.error = "";
      } catch (error) {
        this.sseState.error = `鍵生成エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * キーワードを追加
     */
    addKeyword() {
      if (!this.sseState.keywordInput.trim()) {
        return;
      }
      const keyword = this.sseState.keywordInput.trim();
      if (!this.sseState.keywords.includes(keyword)) {
        this.sseState.keywords.push(keyword);
      }
      this.sseState.keywordInput = "";
    },

    /**
     * キーワードを削除
     */
    removeKeyword(index: number) {
      this.sseState.keywords.splice(index, 1);
    },

    /**
     * SSEで暗号化
     */
    async encryptSSE() {
      if (!this.sseState.masterKey) {
        this.sseState.error = "まずマスター鍵を生成してください";
        return;
      }

      if (!this.sseState.plaintext) {
        this.sseState.error = "平文を入力してください";
        return;
      }

      if (this.sseState.keywords.length === 0) {
        this.sseState.error = "少なくとも1つのキーワードを追加してください";
        return;
      }

      try {
        this.sseState.error = "";
        const plaintextBytes = this.stringToBytes(this.sseState.plaintext);
        this.sseState.plaintextBytes = plaintextBytes;

        const documentId = generateDocumentId();
        this.sseState.documentId = documentId;

        const encrypted = await encryptSSE(
          this.sseState.masterKey,
          documentId,
          plaintextBytes,
          this.sseState.keywords
        );
        this.sseState.encryptedDocument = encrypted;
        this.sseState.documents.push({ id: documentId, document: encrypted });

        // 暗号化成功後、入力フィールドをクリア
        this.sseState.plaintext = "";
        this.sseState.plaintextBytes = null;
        this.sseState.keywords = [];
        this.sseState.keywordInput = "";
      } catch (error) {
        this.sseState.error = `暗号化エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * SSEで検索
     */
    async searchSSE() {
      if (!this.sseState.masterKey) {
        this.sseState.error = "まずマスター鍵を生成してください";
        return;
      }

      if (!this.sseState.searchKeyword.trim()) {
        this.sseState.error = "検索キーワードを入力してください";
        return;
      }

      if (this.sseState.documents.length === 0) {
        this.sseState.error = "検索するドキュメントがありません";
        return;
      }

      try {
        this.sseState.error = "";
        const searchTag = await generateSearchToken(
          this.sseState.masterKey,
          this.sseState.searchKeyword.trim()
        );
        this.sseState.searchTag = searchTag;

        const documentList = this.sseState.documents.map((item) => item.document);
        const results = searchSSE(searchTag, documentList);
        this.sseState.searchResults = this.sseState.documents.filter((item) =>
          results.documents.includes(item.document)
        );

        // 検索結果が1件の場合は自動的に選択
        if (this.sseState.searchResults.length === 1) {
          this.sseState.selectedDocumentId = this.sseState.searchResults[0].id;
        } else {
          // 複数件の場合は選択をクリア
          this.sseState.selectedDocumentId = null;
        }
      } catch (error) {
        this.sseState.error = `検索エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * SSEで復号化
     */
    async decryptSSE() {
      if (!this.sseState.masterKey) {
        this.sseState.error = "まずマスター鍵を生成してください";
        return;
      }

      if (!this.sseState.selectedDocumentId) {
        this.sseState.error = "復号化するドキュメントを選択してください";
        return;
      }

      const documentItem = this.sseState.documents.find((item) => {
        // IDを比較
        if (item.id.length !== this.sseState.selectedDocumentId!.length) {
          return false;
        }
        for (let i = 0; i < item.id.length; i++) {
          if (item.id[i] !== this.sseState.selectedDocumentId![i]) {
            return false;
          }
        }
        return true;
      });

      if (!documentItem) {
        this.sseState.error = "ドキュメントが見つかりません";
        return;
      }

      try {
        this.sseState.error = "";
        const decryptedBytes = await decryptSSE(
          this.sseState.masterKey,
          documentItem.id,
          documentItem.document
        );
        this.sseState.decryptedBytes = decryptedBytes;
        this.sseState.decrypted = this.bytesToString(decryptedBytes);
      } catch (error) {
        this.sseState.error = `復号化エラー: ${error instanceof Error ? error.message : String(error)}`;
      }
    },

    /**
     * ドキュメントを選択
     */
    selectDocument(id: Uint8Array) {
      this.sseState.selectedDocumentId = id;
      this.sseState.error = "";
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
  // 即座に登録（モジュールが読み込まれた時点で利用可能にする）
  // x-initでwindow.cryptoAppが利用可能になるまで待つ処理があるため、
  // モジュールが読み込まれた時点で登録されていれば問題ない
  window.cryptoApp = cryptoApp;
}
