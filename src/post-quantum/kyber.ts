/**
 * CRYSTALS-Kyber（ML-KEM）の実装
 * 
 * このモジュールは、WebAssemblyでコンパイルされたRust実装を使用します。
 * NIST標準化された耐量子暗号アルゴリズム（ML-KEM）を実装しています。
 */

// WebAssemblyモジュールの型定義
import type {
  KyberKeyPair,
  KyberEncapsulation,
} from "../../wasm-src/kyber-wasm/pkg/kyber_wasm.js";

// 型をエクスポート
export type { KyberKeyPair, KyberEncapsulation };

let wasmModule: any | null = null;
let wasmExports: any | null = null;
let isInitialized = false;

/**
 * WebAssemblyモジュールを初期化
 */
export async function initKyber(): Promise<void> {
  if (isInitialized && wasmModule) {
    return;
  }

  try {
    // WebAssemblyモジュールをロード
    const wasmInit = (
      await import("../../wasm-src/kyber-wasm/pkg/kyber_wasm.js")
    ).default;

    // 環境に応じてWasmファイルのパスを決定
    let wasmPath: string;
    
    // Node.js環境（テスト環境など）の場合
    if (typeof process !== "undefined" && process.versions?.node) {
      const { readFileSync } = await import("fs");
      const { fileURLToPath } = await import("url");
      const { dirname, join } = await import("path");
      
      const currentDir = dirname(fileURLToPath(import.meta.url));
      const wasmFilePath = join(
        currentDir,
        "../../wasm-src/kyber-wasm/pkg/kyber_wasm_bg.wasm"
      );
      
      // Node.js環境では直接Wasmファイルを読み込む
      const wasmBuffer = readFileSync(wasmFilePath);
      wasmModule = await wasmInit(wasmBuffer);
    } else {
      // ブラウザ環境の場合
      wasmPath = new URL(
        "../../wasm-src/kyber-wasm/pkg/kyber_wasm_bg.wasm",
        import.meta.url
      ).href;
      wasmModule = await wasmInit({
        module: wasmPath,
      });
    }
    
    wasmModule.init();
    // エクスポートされた関数を取得
    wasmExports = await import("../../wasm-src/kyber-wasm/pkg/kyber_wasm.js");
    isInitialized = true;
  } catch (error) {
    throw new Error(
      `Failed to initialize Kyber WebAssembly module: ${error}`
    );
  }
}

/**
 * Kyber鍵ペアを生成
 * 
 * @returns 公開鍵と秘密鍵のペア
 */
export async function generateKyberKeyPair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  await initKyber();

  // wasmExportsから直接generate_keypair関数を取得
  if (!wasmExports || !wasmExports.generate_keypair) {
    throw new Error("generate_keypair function not found in wasm exports");
  }
  
  // generate_keypairは直接KyberKeyPairを返す（エラー時は例外が投げられる）
  const keypair = wasmExports.generate_keypair();
  
  if (!keypair) {
    throw new Error("Failed to generate Kyber key pair: null result");
  }

  return extractKeyPairData(keypair);
}

/**
 * KyberKeyPairオブジェクトから鍵データを抽出
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
 * 鍵カプセル化（Encapsulation）
 * 公開鍵を使用して共有秘密を生成し、カプセル化する
 * 
 * @param publicKey 公開鍵
 * @returns 暗号文と共有秘密
 */
export async function encapsulateKyber(
  publicKey: Uint8Array
): Promise<{
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}> {
  await initKyber();

  // wasmExportsから直接encapsulate関数を取得
  if (!wasmExports || !wasmExports.encapsulate) {
    throw new Error("encapsulate function not found in wasm exports");
  }
  
  // encapsulateは直接KyberEncapsulationを返す（エラー時は例外が投げられる）
  const result = wasmExports.encapsulate(publicKey);
  if (!result) {
    throw new Error("Failed to encapsulate");
  }

  try {
    return {
      ciphertext: new Uint8Array(result.ciphertext),
      sharedSecret: new Uint8Array(result.shared_secret),
    };
  } finally {
    // メモリリークを防ぐためにリソースを解放
    if (typeof result.free === "function") {
      result.free();
    }
  }
}

/**
 * 鍵デカプセル化（Decapsulation）
 * 秘密鍵と暗号文を使用して共有秘密を復元する
 * 
 * @param ciphertext 暗号文
 * @param privateKey 秘密鍵
 * @param publicKey 公開鍵（秘密鍵の復元に必要）
 * @returns 共有秘密
 */
export async function decapsulateKyber(
  ciphertext: Uint8Array,
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<Uint8Array> {
  await initKyber();

  // wasmExportsから直接decapsulate関数を取得
  if (!wasmExports || !wasmExports.decapsulate) {
    throw new Error("decapsulate function not found in wasm exports");
  }
  
  // decapsulateは直接Vec<u8>を返す（エラー時は例外が投げられる）
  const sharedSecret = wasmExports.decapsulate(
    ciphertext,
    privateKey,
    publicKey
  );
  if (!sharedSecret) {
    throw new Error("Failed to decapsulate");
  }

  // Vec<u8>は自動的にUint8Arrayに変換される
  return new Uint8Array(sharedSecret);
}

