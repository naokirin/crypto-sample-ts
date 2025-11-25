/**
 * IDベース暗号（IBE: Identity-Based Encryption）の実装
 *
 * このモジュールは、WebAssemblyでコンパイルされたRust実装を使用します。
 * Boneh-Franklin IBEスキームを実装しています。
 */

// WebAssemblyモジュールの型定義
import type {
  IBEMasterKey,
  IBEPrivateKey,
  IBEPublicParams,
  InitOutput,
} from "../../wasm-src/ibe-wasm/pkg/ibe_wasm.js";

// 型をエクスポート
export type { IBEMasterKey, IBEPublicParams, IBEPrivateKey };

let wasmModule: InitOutput | null = null;
let isInitialized = false;

/**
 * WebAssemblyモジュールを初期化
 */
export async function initIBE(): Promise<void> {
  if (isInitialized && wasmModule) {
    return;
  }

  try {
    // WebAssemblyモジュールをロード
    const wasmInit = (await import("../../wasm-src/ibe-wasm/pkg/ibe_wasm.js")).default;

    // Wasmファイルのパスを明示的に指定（オブジェクト形式で渡す）
    wasmModule = await wasmInit({
      module_or_path: new URL("../../wasm-src/ibe-wasm/pkg/ibe_wasm_bg.wasm", import.meta.url).href,
    });
    wasmModule.init();
    isInitialized = true;
  } catch (error) {
    throw new Error(`Failed to initialize IBE WebAssembly module: ${error}`);
  }
}

/**
 * IBEのマスター鍵ペアを生成
 *
 * @returns マスター鍵と公開パラメータ
 * @throws Error 初期化されていない場合、または実装が未完成の場合
 */
export async function generateIBEKeyPair(): Promise<{
  masterKey: IBEMasterKey;
  publicParams: IBEPublicParams;
}> {
  await initIBE();

  if (!wasmModule) {
    throw new Error("IBE module not initialized");
  }

  const { IBE } = await import("../../wasm-src/ibe-wasm/pkg/ibe_wasm.js");
  const ibe = new IBE();

  try {
    const result = ibe.setup();
    if (result instanceof Error) {
      throw result;
    }

    // resultはjs_sys::Objectなので、プロパティを取得
    const masterKey = (result as any).master_key;
    const publicParams = (result as any).public_params;

    if (!masterKey || !publicParams) {
      throw new Error("Failed to get master_key or public_params from setup result");
    }

    return {
      masterKey,
      publicParams,
    };
  } catch (error) {
    throw new Error(`IBE setup failed: ${error}`);
  }
}

/**
 * アイデンティティから秘密鍵を抽出
 *
 * @param masterKey マスター鍵
 * @param identity アイデンティティ（文字列）
 * @returns 秘密鍵
 * @throws Error 初期化されていない場合、または実装が未完成の場合
 */
export async function extractIBEKey(
  masterKey: IBEMasterKey,
  identity: string
): Promise<IBEPrivateKey> {
  await initIBE();

  if (!wasmModule) {
    throw new Error("IBE module not initialized");
  }

  const { IBE } = await import("../../wasm-src/ibe-wasm/pkg/ibe_wasm.js");
  const ibe = new IBE();

  try {
    return ibe.extract(masterKey, identity);
  } catch (error) {
    throw new Error(`IBE extract failed: ${error}`);
  }
}

/**
 * メッセージを暗号化
 *
 * @param publicParams 公開パラメータ
 * @param identity アイデンティティ（文字列）
 * @param message 暗号化するメッセージ
 * @returns 暗号文
 * @throws Error 初期化されていない場合、または実装が未完成の場合
 */
export async function encryptIBE(
  publicParams: IBEPublicParams,
  identity: string,
  message: Uint8Array
): Promise<Uint8Array> {
  await initIBE();

  if (!wasmModule) {
    throw new Error("IBE module not initialized");
  }

  const { IBE } = await import("../../wasm-src/ibe-wasm/pkg/ibe_wasm.js");
  const ibe = new IBE();

  try {
    return ibe.encrypt(publicParams, identity, message);
  } catch (error) {
    throw new Error(`IBE encrypt failed: ${error}`);
  }
}

/**
 * 暗号文を復号化
 *
 * @param privateKey 秘密鍵
 * @param ciphertext 暗号文
 * @returns 復号化されたメッセージ
 * @throws Error 初期化されていない場合、または実装が未完成の場合
 */
export async function decryptIBE(
  privateKey: IBEPrivateKey,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  await initIBE();

  if (!wasmModule) {
    throw new Error("IBE module not initialized");
  }

  const { IBE } = await import("../../wasm-src/ibe-wasm/pkg/ibe_wasm.js");
  const ibe = new IBE();

  try {
    return ibe.decrypt(privateKey, ciphertext);
  } catch (error) {
    throw new Error(`IBE decrypt failed: ${error}`);
  }
}

/**
 * 基本的なテスト関数（動作確認用）
 */
export async function testIBE(): Promise<number> {
  await initIBE();

  if (!wasmModule) {
    throw new Error("IBE module not initialized");
  }

  return wasmModule.add(2, 3);
}
