# Crypto Sample TS

TypeScriptで実装された各種暗号技術のサンプルコード集です。

## 概要

このプロジェクトは、各種暗号技術の実装例をTypeScriptで提供することを目的としています。学習や理解を深めるための実用的なサンプルコードを提供します。

## 機能

### 対称鍵暗号
- **AES** (Advanced Encryption Standard) - AES-GCMモード
- **ChaCha20** - XChaCha20-Poly1305
- **Poly1305** - メッセージ認証コード（MAC）

### 非対称鍵暗号
- **RSA** (Rivest-Shamir-Adleman) - RSA-OAEPによる公開鍵暗号
- **ECC** (Elliptic Curve Cryptography) - 楕円曲線暗号
- **IBE** (Identity-Based Encryption) - IDベース暗号
- **ABE** (Attribute-Based Encryption) - 属性ベース暗号

### ハッシュ関数
- **SHA-256** - NIST標準の256ビットハッシュ関数（Web Crypto API使用）
- **SHA-512** - NIST標準の512ビットハッシュ関数（Web Crypto API使用）
- **SHA-3-256** - SHA-3標準の256ビットハッシュ関数（Keccak/Sponge構造）
- **BLAKE2b** - SHA-2より高速な512ビットハッシュ関数
- **BLAKE3** - 並列処理可能な256ビット高速ハッシュ関数
- **SipHash** - 短いメッセージ向けの64ビット鍵付きハッシュ関数（MAC）

## Webデモ

各暗号技術の動作を視覚的に確認できるWebページを提供しています。

### 主な機能

- **対称鍵暗号・非対称鍵暗号**: 鍵生成、暗号化、復号化の各ステップを可視化
- **ハッシュ関数**:
  - 複数のアルゴリズム（SHA-256, SHA-512, SHA-3-256, BLAKE2b, BLAKE3, SipHash）をサポート
  - バイト単位での入力・出力表示
  - 処理時間の計測
  - 比較モード：全アルゴリズムの性能比較機能
  - 16進数・Base64形式での出力表示

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

#### 対称鍵暗号

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

#### ハッシュ関数

```typescript
import { hashSHA256, hashSHA512, hashSHA3_256, hashBLAKE2b, hashBLAKE3 } from "./src/hash/index.js";

// SHA-256でハッシュ値を計算
const input = new TextEncoder().encode("Hello, World!");
const hash = await hashSHA256(input);
console.log(hash); // Uint8Array(32) [...]

// 16進数文字列に変換
const hexHash = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
console.log(hexHash); // "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
```

#### 鍵付きハッシュ関数（SipHash）

```typescript
import { hashSipHash, generateSipHashKey } from "./src/hash/siphash.js";

// 鍵を生成
const key = generateSipHashKey(); // 128ビット (16バイト)

// ハッシュ値を計算
const input = new TextEncoder().encode("Hello, World!");
const hash = await hashSipHash(input, key);
console.log(hash); // Uint8Array(8) [...] (64ビット)
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

