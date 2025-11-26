# Kyber-Wasm: CRYSTALS-Kyber (ML-KEM) WebAssembly実装

このプロジェクトは、NIST標準化された耐量子暗号アルゴリズムであるCRYSTALS-Kyber（ML-KEM）をWebAssemblyでブラウザ上で実行するための実装です。

## 概要

- **アルゴリズム**: CRYSTALS-Kyber (ML-KEM)
- **実装言語**: Rust
- **ビルドツール**: wasm-pack
- **ライブラリ**: pqcrypto-std v0.3.1

## 機能

- 鍵ペア生成（`generate_keypair`）
- 鍵カプセル化（`encapsulate`）
- 鍵デカプセル化（`decapsulate`）

## ビルド方法

```bash
# wasm-packでビルド
wasm-pack build --target web --out-dir pkg
```

## 使用方法

TypeScriptから使用する場合は、`src/post-quantum/kyber.ts`を参照してください。

```typescript
import { 
  initKyber, 
  generateKyberKeyPair, 
  encapsulateKyber, 
  decapsulateKyber 
} from './post-quantum/kyber';

// 初期化
await initKyber();

// 鍵ペア生成
const { publicKey, privateKey } = await generateKyberKeyPair();

// カプセル化
const { ciphertext, sharedSecret } = await encapsulateKyber(publicKey);

// デカプセル化
const decapsulatedSecret = await decapsulateKyber(
  ciphertext, 
  privateKey, 
  publicKey
);
```

## 依存関係

- `pqcrypto-std`: NIST標準化された耐量子暗号プリミティブ
- `wasm-bindgen`: RustとJavaScript間のバインディング
- `rand`: 乱数生成

## 注意事項

- この実装はプロトタイプです
- 本番環境で使用する前に、セキュリティレビューを実施してください
- パフォーマンステストを実施してください

