# Crypto Sample TS

TypeScriptで実装された各種暗号技術のサンプルコード集です。

## 概要

このプロジェクトは、各種暗号技術の実装例をTypeScriptで提供することを目的としています。学習や理解を深めるための実用的なサンプルコードを提供します。

## 機能

### 対称鍵暗号
- **AES** (Advanced Encryption Standard) - AES-GCMモード
- **ChaCha20** - XChaCha20-Poly1305
- **Poly1305** - メッセージ認証コード（MAC）

## Webデモ

各暗号技術の動作を視覚的に確認できるWebページを提供しています。

### 開発サーバーの起動

```bash
npm run web:dev
```

ブラウザで `http://localhost:3000` にアクセスすると、Webページが表示されます。

### ビルド

```bash
npm run web:build
```

ビルドされたファイルは `dist-web/` ディレクトリに出力されます。

### プレビュー

```bash
npm run web:preview
```

ビルドされたファイルをプレビューできます。

## 使用方法

### Webページでの使用方法

1. 開発サーバーを起動: `npm run web:dev`
2. ブラウザで `http://localhost:3000` にアクセス
3. 暗号技術を選択
4. 各ステップ（鍵生成、暗号化、復号化など）を実行

### プログラムでの使用方法

```typescript
import { encryptAES, decryptAES, generateAESKey } from "./src/symmetric/aes.js";

// 鍵を生成
const key = generateAESKey();

// 平文を暗号化
const plaintext = new TextEncoder().encode("Hello, World!");
const result = encryptAES(plaintext, key);

// 復号化
const decrypted = decryptAES(result.ciphertext, key, result.iv, result.authTag);
const message = new TextDecoder().decode(decrypted);
console.log(message); // "Hello, World!"
```

## 開発

### ビルド

```bash
npm run build
```

### テスト

```bash
npm test
```

### リンター・フォーマッター

```bash
npm run lint
npm run lint:fix
npm run format
```

## 技術スタック

- **言語**: TypeScript
- **パッケージマネージャー**: npm
- **リンター・フォーマッター**: Biome
- **テストフレームワーク**: Vitest
- **ビルドツール**: Vite
- **フロントエンドフレームワーク**: Alpine.js

## ライセンス

MIT

