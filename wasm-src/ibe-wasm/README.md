# IBE WebAssembly実装

このディレクトリには、IDベース暗号（IBE: Identity-Based Encryption）のWebAssembly実装が含まれています。

## 実装状況

### 完了した項目

- ✅ Rustプロジェクトのセットアップ
- ✅ wasm-packのインストールと設定
- ✅ Miracl Coreの依存関係追加
- ✅ 基本的な型定義（IBE、IBEMasterKey、IBEPublicParams、IBEPrivateKey）
- ✅ WebAssemblyビルドの成功
- ✅ TypeScriptラッパーの作成

### 実装予定の項目

- ⏳ Miracl Coreを使用したペアリング演算の実装
- ⏳ Boneh-Franklin IBEスキームの実装
  - Setup（マスター鍵ペアの生成）
  - Extract（アイデンティティから秘密鍵を抽出）
  - Encrypt（メッセージの暗号化）
  - Decrypt（暗号文の復号化）

## ビルド方法

```bash
cd wasm-src/ibe-wasm
wasm-pack build --target web --out-dir pkg
```

## 使用方法

TypeScriptから以下のように使用できます：

```typescript
import { initIBE, generateIBEKeyPair, extractIBEKey, encryptIBE, decryptIBE } from './asymmetric/ibe';

// 初期化
await initIBE();

// マスター鍵ペアの生成
const { masterKey, publicParams } = await generateIBEKeyPair();

// アイデンティティから秘密鍵を抽出
const identity = "user@example.com";
const privateKey = await extractIBEKey(masterKey, identity);

// メッセージの暗号化
const message = new TextEncoder().encode("Hello, IBE!");
const ciphertext = await encryptIBE(publicParams, identity, message);

// 暗号文の復号化
const decrypted = await decryptIBE(privateKey, ciphertext);
```

## 注意事項

現在、IBEの実装は基本的な構造のみが完成しており、実際の暗号化/復号化機能は未実装です。

Miracl Coreのドキュメントを参照しながら、以下の実装が必要です：

1. ペアリング演算の理解と実装
2. Boneh-Franklin IBEスキームの各アルゴリズムの実装
3. セキュリティ面での検証

## 参考資料

- [Miracl Core公式リポジトリ](https://github.com/miracl/core)
- [Miracl Core Rustドキュメント](https://docs.rs/crate/miracl_core/2.7.0)
- [Boneh-Franklin IBE論文](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf)

