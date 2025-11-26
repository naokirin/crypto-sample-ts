/**
 * CRYSTALS-Dilithium（ML-DSA）の実装
 * 
 * このモジュールは、WebAssemblyでコンパイルされたRust実装を使用します。
 * NIST標準化された耐量子暗号アルゴリズム（ML-DSA）を実装しています。
 */

// WebAssemblyモジュールの型定義
import type { DilithiumKeyPair } from "../../wasm-src/dilithium-wasm/pkg/dilithium_wasm.js";

// 型をエクスポート
export type { DilithiumKeyPair };

let wasmModule: any | null = null;
let wasmExports: any | null = null;
let isInitialized = false;

/**
 * WebAssemblyモジュールを初期化
 */
export async function initDilithium(): Promise<void> {
  if (isInitialized && wasmModule) {
    return;
  }

  try {
    // WebAssemblyモジュールをロード
    const wasmInit = (
      await import("../../wasm-src/dilithium-wasm/pkg/dilithium_wasm.js")
    ).default;

    // 環境に応じてWasmファイルのパスを決定
    // Node.js環境（テスト環境など）の場合
    if (typeof process !== "undefined" && process.versions?.node) {
      const { readFileSync } = await import("fs");
      const { fileURLToPath } = await import("url");
      const { dirname, join } = await import("path");
      
      const currentDir = dirname(fileURLToPath(import.meta.url));
      const wasmFilePath = join(
        currentDir,
        "../../wasm-src/dilithium-wasm/pkg/dilithium_wasm_bg.wasm"
      );
      
      // Node.js環境では直接Wasmファイルを読み込む
      const wasmBuffer = readFileSync(wasmFilePath);
      wasmModule = await wasmInit(wasmBuffer);
    } else {
      // ブラウザ環境の場合
      const wasmPath = new URL(
        "../../wasm-src/dilithium-wasm/pkg/dilithium_wasm_bg.wasm",
        import.meta.url
      ).href;
      wasmModule = await wasmInit({
        module: wasmPath,
      });
    }
    
    wasmModule.init();
    // エクスポートされた関数を取得
    wasmExports = await import("../../wasm-src/dilithium-wasm/pkg/dilithium_wasm.js");
    isInitialized = true;
  } catch (error) {
    throw new Error(
      `Failed to initialize Dilithium WebAssembly module: ${error}`
    );
  }
}

/**
 * Dilithium鍵ペアを生成
 * 
 * @returns 公開鍵と秘密鍵のペア
 */
export async function generateDilithiumKeyPair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  await initDilithium();

  // wasmExportsから直接generate_keypair関数を取得
  if (!wasmExports || !wasmExports.generate_keypair) {
    throw new Error("generate_keypair function not found in wasm exports");
  }
  
  // generate_keypairは直接DilithiumKeyPairを返す（エラー時は例外が投げられる）
  const keypair = wasmExports.generate_keypair();
  
  if (!keypair) {
    throw new Error("Failed to generate Dilithium key pair: null result");
  }

  return extractKeyPairData(keypair);
}

/**
 * DilithiumKeyPairオブジェクトから鍵データを抽出
 */
function extractKeyPairData(keypair: any): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  try {
    // プロパティを取得（getterとして定義されている）
    const publicKey = keypair.public_key;
    const privateKey = keypair.private_key;

    if (!publicKey || publicKey.length === 0) {
      throw new Error(`Failed to get public key data. keypair type: ${typeof keypair}, publicKey: ${publicKey}, privateKey: ${privateKey}`);
    }
    
    if (!privateKey || privateKey.length === 0) {
      throw new Error(`Failed to get private key data. keypair type: ${typeof keypair}, publicKey: ${publicKey}, privateKey: ${privateKey}`);
    }

    // Uint8Arrayとして返す（既にUint8Arrayの可能性があるが、念のため）
    return {
      publicKey: publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey),
      privateKey: privateKey instanceof Uint8Array ? privateKey : new Uint8Array(privateKey),
    };
  } finally {
    // メモリリークを防ぐためにリソースを解放
    if (typeof keypair.free === "function") {
      keypair.free();
    }
  }
}

/**
 * メッセージに署名
 * 
 * @param message 署名するメッセージ
 * @param privateKey 秘密鍵
 * @returns 署名
 */
export async function signDilithium(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  await initDilithium();

  // wasmExportsから直接sign関数を取得
  if (!wasmExports || !wasmExports.sign) {
    throw new Error("sign function not found in wasm exports");
  }
  
  // signは直接Vec<u8>を返す（エラー時は例外が投げられる）
  const signature = wasmExports.sign(message, privateKey);
  if (!signature) {
    throw new Error("Failed to sign");
  }

  // Vec<u8>は自動的にUint8Arrayに変換される
  return new Uint8Array(signature);
}

/**
 * 署名を検証
 * 
 * @param message 元のメッセージ
 * @param signature 署名
 * @param publicKey 公開鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export async function verifyDilithium(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  await initDilithium();

  // wasmExportsから直接verify関数を取得
  if (!wasmExports || !wasmExports.verify) {
    throw new Error("verify function not found in wasm exports");
  }
  
  // verifyは直接boolを返す
  return wasmExports.verify(message, signature, publicKey);
}

