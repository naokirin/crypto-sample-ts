/**
 * 属性ベース暗号（ABE: Attribute-Based Encryption）の実装
 *
 * このモジュールは、WebAssemblyでコンパイルされたRust実装を使用します。
 * CP-ABE (Ciphertext-Policy Attribute-Based Encryption) スキームを実装しています。
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
