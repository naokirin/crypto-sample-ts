/**
 * 属性ベース暗号（ABE: Attribute-Based Encryption）の実装
 *
 * このモジュールは、WebAssemblyでコンパイルされたRust実装を使用します。
 * CP-ABE (Ciphertext-Policy Attribute-Based Encryption) と
 * KP-ABE (Key-Policy Attribute-Based Encryption) の両方のスキームを実装しています。
 */

// WebAssemblyモジュールの型定義
import type {
  ABEMasterKey,
  ABEPrivateKey,
  ABEPublicParams,
  InitOutput,
} from "../../wasm-src/abe-wasm/pkg/abe_wasm.js";

// 型をエクスポート
export type { ABEMasterKey, ABEPublicParams, ABEPrivateKey };

let wasmModule: InitOutput | null = null;
let isInitialized = false;

/**
 * WebAssemblyモジュールを初期化
 */
export async function initABE(): Promise<void> {
  if (isInitialized && wasmModule) {
    return;
  }

  try {
    // WebAssemblyモジュールをロード
    const wasmInit = (await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js")).default;

    // Wasmファイルのパスを明示的に指定（オブジェクト形式で渡す）
    wasmModule = await wasmInit({
      module_or_path: new URL("../../wasm-src/abe-wasm/pkg/abe_wasm_bg.wasm", import.meta.url).href,
    });
    wasmModule.init();
    isInitialized = true;
  } catch (error) {
    throw new Error(`Failed to initialize ABE WebAssembly module: ${error}`);
  }
}

/**
 * ABEのマスター鍵ペアを生成
 */
export async function generateABEKeyPair(): Promise<{
  masterKey: ABEMasterKey;
  publicParams: ABEPublicParams;
}> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  const { ABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
  const abe = new ABE();
  const result = abe.setup();

  if (!result || typeof result !== "object") {
    throw new Error("Failed to generate ABE key pair");
  }

  const masterKey = (result as any).master_key as ABEMasterKey;
  const publicParams = (result as any).public_params as ABEPublicParams;

  return { masterKey, publicParams };
}

/**
 * 属性セットから秘密鍵を生成
 */
export async function extractABEKey(
  masterKey: ABEMasterKey,
  attributes: string[]
): Promise<ABEPrivateKey> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  const { ABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
  const abe = new ABE();
  const privateKey = abe.key_gen(masterKey, attributes);

  if (!privateKey) {
    throw new Error("Failed to extract ABE private key");
  }

  return privateKey;
}

/**
 * メッセージを暗号化
 * @param publicParams 公開パラメータ
 * @param policy アクセスポリシー（カンマ区切りの属性リスト、例: "A,B,C"）
 * @param message 暗号化するメッセージ
 */
export async function encryptABE(
  publicParams: ABEPublicParams,
  policy: string,
  message: Uint8Array
): Promise<Uint8Array> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  const { ABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
  const abe = new ABE();

  try {
    return abe.encrypt(publicParams, policy, message);
  } catch (error) {
    throw new Error(`ABE encrypt failed: ${error}`);
  }
}

/**
 * 暗号文を復号化
 */
export async function decryptABE(
  privateKey: ABEPrivateKey,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  const { ABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
  const abe = new ABE();

  try {
    return abe.decrypt(privateKey, ciphertext);
  } catch (error) {
    throw new Error(`ABE decrypt failed: ${error}`);
  }
}

/**
 * 基本的な動作確認用のテスト関数
 */
export async function testABE(): Promise<boolean> {
  try {
    await initABE();
    if (!wasmModule) {
      return false;
    }

    const { add } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
    const result = add(2, 3);
    return result === 5;
  } catch (error) {
    console.error("ABE test failed:", error);
    return false;
  }
}

// ============================================================================
// KP-ABE (Key-Policy Attribute-Based Encryption) 関数
// ============================================================================

/**
 * KP-ABEのマスター鍵ペアを生成
 * KP-ABEでは、鍵生成時にポリシーを指定し、暗号化時に属性セットを指定します。
 */
export async function generateKPABEKeyPair(): Promise<{
  masterKey: ABEMasterKey;
  publicParams: ABEPublicParams;
}> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  try {
    const { KPABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
    const kpabe = new KPABE();
    const result = kpabe.setup();

    if (!result || typeof result !== "object") {
      throw new Error("Failed to generate KP-ABE key pair");
    }

    const masterKey = (result as any).master_key as ABEMasterKey;
    const publicParams = (result as any).public_params as ABEPublicParams;

    if (!masterKey || !publicParams) {
      throw new Error("Invalid KP-ABE key pair structure");
    }

    return { masterKey, publicParams };
  } catch (error) {
    throw new Error(`KP-ABE key pair generation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * ポリシー（属性リスト）から秘密鍵を生成
 * KP-ABEでは、鍵生成時にポリシーを指定します。
 * @param masterKey マスター鍵
 * @param policy アクセスポリシー（カンマ区切りの属性リスト、例: "A,B,C"）
 */
export async function extractKPABEKey(
  masterKey: ABEMasterKey,
  policy: string
): Promise<ABEPrivateKey> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  try {
    const { KPABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
    const kpabe = new KPABE();
    const privateKey = kpabe.key_gen(masterKey, policy);

    if (!privateKey) {
      throw new Error("Failed to extract KP-ABE private key");
    }

    return privateKey;
  } catch (error) {
    throw new Error(`KP-ABE key extraction failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * 属性セットからメッセージを暗号化
 * KP-ABEでは、暗号化時に属性セットを指定します。
 * @param publicParams 公開パラメータ
 * @param attributes 属性セット（例: ["A", "B", "C"]）
 * @param message 暗号化するメッセージ
 */
export async function encryptKPABE(
  publicParams: ABEPublicParams,
  attributes: string[],
  message: Uint8Array
): Promise<Uint8Array> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  const { KPABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
  const kpabe = new KPABE();

  try {
    return kpabe.encrypt(publicParams, attributes, message);
  } catch (error) {
    throw new Error(`KP-ABE encrypt failed: ${error}`);
  }
}

/**
 * 暗号文を復号化
 * KP-ABEでは、暗号文の属性セットが鍵のポリシーを満たす場合のみ復号可能です。
 */
export async function decryptKPABE(
  privateKey: ABEPrivateKey,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  await initABE();
  if (!wasmModule) {
    throw new Error("ABE module not initialized");
  }

  const { KPABE } = await import("../../wasm-src/abe-wasm/pkg/abe_wasm.js");
  const kpabe = new KPABE();

  try {
    return kpabe.decrypt(privateKey, ciphertext);
  } catch (error) {
    throw new Error(`KP-ABE decrypt failed: ${error}`);
  }
}
