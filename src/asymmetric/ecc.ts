/**
 * ECC (Elliptic Curve Cryptography) のサンプル実装
 *
 * ECCは、楕円曲線上の離散対数問題の困難性を利用した非対称鍵暗号です。
 * RSAと比較して、同じセキュリティ強度をより短い鍵長で実現できます。
 *
 * この実装では、以下の楕円曲線をサポートします:
 * - secp256k1: Bitcoinで使用される曲線
 * - P-256, P-384, P-521: NIST推奨曲線
 * - Ed25519, Ed448: Edwards曲線（EdDSA署名に使用）
 */

import { ed448 } from "@noble/curves/ed448.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256, p384, p521 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

/**
 * サポートする楕円曲線の種類
 */
export type CurveType = "secp256k1" | "p256" | "p384" | "p521" | "ed25519" | "ed448";

/**
 * ECDHをサポートする楕円曲線の種類
 */
export type EcdhSupportedCurve = "secp256k1" | "p256" | "p384" | "p521";

/**
 * 曲線がECDHをサポートしているかどうかを判定する型ガード
 */
function isEcdhSupportedCurve(curve: CurveType): curve is EcdhSupportedCurve {
  return curve === "secp256k1" || curve === "p256" || curve === "p384" || curve === "p521";
}

/**
 * ECC鍵ペア
 */
export interface EccKeyPair {
  /** 秘密鍵（16進数文字列） */
  privateKey: string;
  /** 公開鍵（16進数文字列） */
  publicKey: string;
  /** 使用する曲線 */
  curve: CurveType;
}

/**
 * ECDSA署名結果
 */
export interface EcdsaSignatureResult {
  /** 署名（16進数文字列） */
  signature: string;
  /** リカバリID（secp256k1の場合のみ） */
  recoveryId?: number;
}

/**
 * ECDH鍵共有結果
 */
export interface EcdhResult {
  /** 共有秘密鍵（16進数文字列） */
  sharedSecret: string;
}

/**
 * 曲線に応じた曲線オブジェクトを取得
 */
function getCurve(curve: CurveType) {
  switch (curve) {
    case "secp256k1":
      return secp256k1;
    case "p256":
      return p256;
    case "p384":
      return p384;
    case "p521":
      return p521;
    case "ed25519":
      return ed25519;
    case "ed448":
      return ed448;
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}

/**
 * ECC鍵ペアを生成します。
 *
 * @param curve - 使用する楕円曲線（デフォルト: secp256k1）
 * @returns ECC鍵ペア
 */
export function generateEccKeyPair(curve: CurveType = "secp256k1"): EccKeyPair {
  const curveObj = getCurve(curve);
  const privateKey = curveObj.utils.randomSecretKey();
  const publicKey = curveObj.getPublicKey(privateKey);

  return {
    privateKey: Buffer.from(privateKey).toString("hex"),
    publicKey: Buffer.from(publicKey).toString("hex"),
    curve,
  };
}

/**
 * ECDSAを使用してデータに署名します。
 *
 * @param message - 署名するメッセージ（バイト配列）
 * @param privateKeyHex - 秘密鍵（16進数文字列）
 * @param curve - 使用する楕円曲線（デフォルト: secp256k1）
 * @returns 署名結果
 * @throws 秘密鍵が不正な場合、または署名に失敗した場合にエラーをスローします。
 */
export function signEcdsa(
  message: Uint8Array,
  privateKeyHex: string,
  curve: CurveType = "secp256k1"
): EcdsaSignatureResult {
  try {
    const curveObj = getCurve(curve);
    const privateKey = Buffer.from(privateKeyHex, "hex");

    // Ed25519とEd448はEdDSAを使用
    if (curve === "ed25519" || curve === "ed448") {
      const signature = curveObj.sign(message, privateKey);
      // EdDSAの署名はUint8Arrayを直接返す
      const signatureBytes =
        signature instanceof Uint8Array ? signature : new Uint8Array(signature);
      return {
        signature: Buffer.from(signatureBytes).toString("hex"),
      };
    }

    // その他の曲線はECDSAを使用
    const signature = curveObj.sign(message, privateKey);
    // ECDSAの署名はUint8ArrayまたはSignatureオブジェクトを返す
    const signatureBytes = signature instanceof Uint8Array ? signature : new Uint8Array(signature);
    const signatureHex = Buffer.from(signatureBytes).toString("hex");

    // secp256k1の場合はリカバリIDも返す
    if (curve === "secp256k1" && typeof signature === "object" && "recovery" in signature) {
      return {
        signature: signatureHex,
        recoveryId: (signature as { recovery?: number }).recovery,
      };
    }

    return {
      signature: signatureHex,
    };
  } catch (error) {
    throw new Error(
      `ECDSA signing failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * ECDSAを使用して署名を検証します。
 *
 * @param message - 検証するメッセージ（バイト配列）
 * @param signatureHex - 署名（16進数文字列）
 * @param publicKeyHex - 公開鍵（16進数文字列）
 * @param curve - 使用する楕円曲線（デフォルト: secp256k1）
 * @returns 署名が有効な場合true、無効な場合false
 * @throws 公開鍵が不正な場合、または検証処理に失敗した場合にエラーをスローします。
 */
export function verifyEcdsa(
  message: Uint8Array,
  signatureHex: string,
  publicKeyHex: string,
  curve: CurveType = "secp256k1"
): boolean {
  try {
    const curveObj = getCurve(curve);
    const publicKey = Buffer.from(publicKeyHex, "hex");
    const signature = Buffer.from(signatureHex, "hex");

    // Ed25519とEd448はEdDSAを使用
    if (curve === "ed25519" || curve === "ed448") {
      return curveObj.verify(signature, message, publicKey);
    }

    // その他の曲線はECDSAを使用
    return curveObj.verify(signature, message, publicKey);
  } catch (error) {
    // 無効な署名の場合はfalseを返す
    if (error instanceof Error && error.message.includes("Invalid signature")) {
      return false;
    }
    throw new Error(
      `ECDSA verification failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * ECDHをサポートする曲線オブジェクトの型
 */
interface EcdhCurve {
  getSharedSecret: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array;
}

/**
 * ECDH（楕円曲線Diffie-Hellman）を使用して共有秘密鍵を生成します。
 *
 * @param privateKeyHex - 自分の秘密鍵（16進数文字列）
 * @param publicKeyHex - 相手の公開鍵（16進数文字列）
 * @param curve - 使用する楕円曲線（ECDHをサポートする曲線のみ）
 * @returns 共有秘密鍵
 * @throws 鍵が不正な場合、または鍵共有に失敗した場合にエラーをスローします。
 */
export function computeEcdh(
  privateKeyHex: string,
  publicKeyHex: string,
  curve: EcdhSupportedCurve = "secp256k1"
): EcdhResult {
  try {
    const curveObj = getCurve(curve);
    const privateKey = Buffer.from(privateKeyHex, "hex");
    const publicKey = Buffer.from(publicKeyHex, "hex");

    // 型ガードでECDHをサポートする曲線であることを確認
    if (!isEcdhSupportedCurve(curve)) {
      throw new Error(`ECDH is not supported for ${curve}`);
    }

    // 型アサーション: ECDHをサポートする曲線はgetSharedSecretメソッドを持つ
    const ecdhCurve = curveObj as EcdhCurve;
    const sharedSecret = ecdhCurve.getSharedSecret(privateKey, publicKey);

    return {
      sharedSecret: Buffer.from(sharedSecret).toString("hex"),
    };
  } catch (error) {
    throw new Error(
      `ECDH computation failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * EdDSAを使用してデータに署名します（Ed25519/Ed448専用）。
 *
 * @param message - 署名するメッセージ（バイト配列）
 * @param privateKeyHex - 秘密鍵（16進数文字列）
 * @param curve - 使用する楕円曲線（ed25519またはed448）
 * @returns 署名結果
 * @throws 曲線がEdDSAをサポートしていない場合、または署名に失敗した場合にエラーをスローします。
 */
export function signEddsa(
  message: Uint8Array,
  privateKeyHex: string,
  curve: "ed25519" | "ed448" = "ed25519"
): EcdsaSignatureResult {
  return signEcdsa(message, privateKeyHex, curve);
}

/**
 * EdDSAを使用して署名を検証します（Ed25519/Ed448専用）。
 *
 * @param message - 検証するメッセージ（バイト配列）
 * @param signatureHex - 署名（16進数文字列）
 * @param publicKeyHex - 公開鍵（16進数文字列）
 * @param curve - 使用する楕円曲線（ed25519またはed448）
 * @returns 署名が有効な場合true、無効な場合false
 * @throws 曲線がEdDSAをサポートしていない場合、または検証処理に失敗した場合にエラーをスローします。
 */
export function verifyEddsa(
  message: Uint8Array,
  signatureHex: string,
  publicKeyHex: string,
  curve: "ed25519" | "ed448" = "ed25519"
): boolean {
  return verifyEcdsa(message, signatureHex, publicKeyHex, curve);
}
