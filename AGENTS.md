# AGENTS.md

このドキュメントは、TypeScriptで暗号技術のサンプルコードを作成する際のガイドラインです。

## プロジェクトの目的

このプロジェクトは、各種暗号技術の実装例をTypeScriptで提供することを目的としています。学習や理解を深めるための実用的なサンプルコードを提供します。

## コーディングスタイル

- **言語**: TypeScript
- **パッケージマネージャー**: npm
- **リンター・フォーマッター**: biome
- **コードスタイル**: 明確で読みやすいコードを心がける
- **コメント**: 複雑な処理や暗号学的な概念には適切な説明を追加

## ファイル構造

```
crypto-sample-ts/
├── src/
│   ├── symmetric/          # 対称鍵暗号
│   ├── asymmetric/         # 非対称鍵暗号
│   ├── hash/               # ハッシュ関数
│   ├── digital-signature/  # デジタル署名
│   ├── key-exchange/       # 鍵交換
│   ├── post-quantum/       # 耐量子暗号
│   ├── searchable/         # 検索可能暗号
│   ├── utils/              # ユーティリティ関数
│   └── web/                # Webページ用のTypeScriptコード
├── tests/                  # テストファイル
├── docs/                   # ドキュメント
├── dist-web/               # Webページのビルド出力
├── index.html              # WebページのメインHTMLファイル
├── vite.config.ts          # Viteの設定ファイル
├── package.json            # プロジェクトの依存関係とスクリプト
├── tsconfig.json           # TypeScriptの設定
├── biome.json              # リンター・フォーマッターの設定
└── .gitignore              # Gitの除外設定
```

## サンプルコード作成の方針

### 1. 各暗号技術のサンプルには以下を含める

- **基本的な使用例**: 最もシンプルな使用パターン
- **エラーハンドリング**: 適切なエラー処理の例
- **型安全性**: TypeScriptの型を活用した安全な実装
- **コメント**: 暗号学的な概念や処理の説明

### 2. 実装の原則

- **セキュリティ**: 実装例であっても、セキュリティのベストプラクティスに従う
- **明確性**: コードは教育的な目的も兼ねているため、理解しやすさを重視
- **実用性**: 実際の使用場面を想定した実装例を提供

### 3. ドキュメント

- 各サンプルコードには、その暗号技術の基本的な説明を含める
- 数学的な定義を使用する場合は、事前に説明を追加する
- ストーリーとして理解しやすい流れで記述する
- 例えや前置きを多用せず、簡潔に記述する

## 対応予定の暗号技術

### 対称鍵暗号
- AES (Advanced Encryption Standard)
- ChaCha20
- Poly1305 (認証付き暗号)
- その他

### 非対称鍵暗号
- RSA
- ECC (Elliptic Curve Cryptography)
- IDベース暗号 (Identity-Based Encryption) - 後回し（複雑なため）
- 属性ベース暗号 (Attribute-Based Encryption) - 後回し（複雑なため）
- その他

### ハッシュ関数
- ✅ SHA-256 (NIST標準、Web Crypto API使用)
- ✅ SHA-512 (NIST標準、Web Crypto API使用)
- ✅ SHA-3-256 (NIST標準、Keccak/Sponge構造)
- ✅ BLAKE2b (高速・512ビット出力)
- ✅ BLAKE3 (並列処理可能・256ビット出力)
- ✅ SipHash (鍵付きハッシュ関数/MAC、64ビット出力)
- その他 (未実装)

### デジタル署名
- RSA署名
- ECDSA
- EdDSA
- 匿名署名 (Anonymous Signature)
- その他

### 鍵交換
- Diffie-Hellman
- ECDH
- その他

### 検索可能暗号
- 検索可能暗号 (Searchable Encryption)

### 耐量子暗号 (Post-Quantum Cryptography)
NIST標準選定された耐量子暗号:
- **鍵交換**
  - ✅ CRYSTALS-Kyber (ML-KEM) - Rust + wasm-pack実装完了
- **デジタル署名**
  - CRYSTALS-Dilithium (ML-DSA)
  - FALCON
  - SPHINCS+

## 非対称鍵暗号の実装方針

### 実装対象

まずはRSAとECCから実装を開始します。IBE/ABEは複雑なため、後回しにします。

### RSA（Rivest-Shamir-Adleman）

**使用ライブラリ**: `node-forge`

**理由:**
- ブラウザとNode.jsの両方で動作
- RSAの鍵生成、暗号化/復号化、署名/検証をサポート
- TypeScriptの型定義が利用可能
- 実績があり、広く使用されている

**実装する機能:**
- RSA鍵ペアの生成（2048ビット、4096ビット）
- RSA-OAEPによる暗号化/復号化
- RSA署名と検証
- PEM形式での鍵のエクスポート/インポート

**実装ファイル:**
- `src/asymmetric/rsa.ts`

**テストファイル:**
- `tests/asymmetric/rsa.test.ts`

### ECC（Elliptic Curve Cryptography）

**使用ライブラリ**: `@noble/curves`

**理由:**
- ブラウザとNode.jsの両方で動作
- 既存の`@noble/ciphers`と一貫性がある
- TypeScript対応で軽量かつセキュア
- 多数の楕円曲線をサポート

**実装する機能:**
- 主要な楕円曲線のサポート:
  - secp256k1（Bitcoinで使用）
  - P-256、P-384、P-521（NIST推奨曲線）
  - Ed25519、Ed448（Edwards曲線）
- 秘密鍵/公開鍵の生成
- ECDH（楕円曲線Diffie-Hellman鍵交換）
- ECDSA署名と検証
- EdDSA署名と検証

**実装ファイル:**
- `src/asymmetric/ecc.ts`

**テストファイル:**
- `tests/asymmetric/ecc.test.ts`

### IBE/ABEについて

IDベース暗号（IBE）と属性ベース暗号（ABE）は、ペアリングベースの暗号技術を使用するため、実装が複雑で計算量も多いです。現時点では実装を後回しにし、詳細な調査結果は`docs/asymmetric-libraries.md`に記載しています。

将来的な実装方針:
- WebAssembly（Wasm）を活用した実装を検討
- 純粋なTypeScriptによる参考実装も調査
- 詳細は`docs/asymmetric-libraries.md`を参照

## ハッシュ関数の実装方針

### 実装対象

ブラウザ環境で動作する6種類のハッシュ関数を実装しました。

### 実装したアルゴリズム

#### SHA-256 / SHA-512

**使用技術**: Web Crypto API（ブラウザネイティブ）

**理由:**
- ブラウザネイティブ実装で高速
- 追加ライブラリ不要
- セキュリティが保証されている
- 非同期APIで一貫性がある

**特徴:**
- SHA-256: 256ビット（32バイト）出力、NIST標準
- SHA-512: 512ビット（64バイト）出力、NIST標準
- Merkle-Damgård構造

**実装ファイル:**
- `src/hash/sha256.ts`
- `src/hash/sha512.ts`

#### SHA-3-256

**使用ライブラリ**: `@noble/hashes`

**理由:**
- Web Crypto APIはSHA-3未対応
- 純粋なTypeScript実装で依存関係がない
- セキュアで高速
- ブラウザとNode.jsの両方で動作

**特徴:**
- 256ビット（32バイト）出力、NIST標準
- Sponge構造（Keccak）
- SHA-2の代替として標準化

**実装ファイル:**
- `src/hash/sha3-256.ts`

#### BLAKE2b

**使用ライブラリ**: `@noble/hashes`

**特徴:**
- 512ビット（64バイト）出力
- SHA-2より高速で安全性も高い
- HAIFA構造（ARXベース）
- 暗号通貨などで広く採用

**実装ファイル:**
- `src/hash/blake2b.ts`

#### BLAKE3

**使用ライブラリ**: `@noble/hashes`

**特徴:**
- 256ビット（32バイト）出力
- BLAKE2の後継、並列処理可能
- 非常に高速
- Merkle tree構造

**実装ファイル:**
- `src/hash/blake3.ts`

#### SipHash

**使用ライブラリ**: `siphash` (npmパッケージ)

**理由:**
- `@noble/hashes`にはSipHashが含まれていない
- ブラウザ環境で動作する実装が必要

**特徴:**
- 64ビット（8バイト）出力
- 鍵付きハッシュ関数（MAC）
- 128ビット（16バイト）の鍵が必要
- 短いメッセージに特化した高速なMAC
- ARX構造
- ハッシュテーブルのDoS攻撃対策として使用

**実装ファイル:**
- `src/hash/siphash.ts`

**実装の注意点:**
- `siphash`ライブラリはUint32Array形式の鍵を要求
- Uint8Array ⇔ Uint32Array の変換処理を実装
- リトルエンディアン形式で変換

### 共通仕様

**API設計:**
- すべてのハッシュ関数は統一された非同期API
- 入力: `Uint8Array`
- 出力: `Promise<Uint8Array>`

**型定義:**
```typescript
export type HashFunction = (input: Uint8Array) => Promise<Uint8Array>;
export type KeyedHashFunction = (input: Uint8Array, key: Uint8Array) => Promise<Uint8Array>;
```

**テスト:**
- 公式テストベクター（NIST、各アルゴリズムの公式仕様）を使用
- 空文字列、短いメッセージ、長いメッセージなど多様な入力サイズでテスト
- 決定性、衝突困難性の検証
- SipHashは鍵依存性のテスト

**テストファイル:**
- `tests/hash/sha256.test.ts`
- `tests/hash/sha512.test.ts`
- `tests/hash/sha3-256.test.ts`
- `tests/hash/blake2b.test.ts`
- `tests/hash/blake3.test.ts`
- `tests/hash/siphash.test.ts`

### Web UI機能

ハッシュ関数のWebデモには以下の機能を実装しています：

1. **アルゴリズム選択**: 6種類のハッシュ関数から選択可能
2. **比較モード**: 全アルゴリズムの性能を同時に比較
3. **詳細表示**:
   - 入力データのバイト単位表示（16進数）
   - 処理時間の計測
   - ハッシュ値の複数形式表示（16進数、Base64、バイト単位）
4. **SipHash専用機能**: 128ビット鍵の生成機能
5. **教育的な説明**:
   - 各アルゴリズムの特徴
   - ハッシュ関数の性質（一方向性、決定性、固定長出力、衝突困難性、雪崩効果）
   - 構造の違い（Merkle-Damgård、Sponge、HAIFA、ARX）

## Webデモ

各暗号技術の動作を視覚的に確認できるWebページを提供しています。

### 技術スタック

- **ビルドツール**: Vite
- **フロントエンドフレームワーク**: Alpine.js
- **スタイリング**: インラインCSS（シンプルな実装）

### 機能

Webページでは以下の機能を提供します：

1. **暗号技術の選択**: ドロップダウンから暗号技術を選択
2. **鍵生成**: 各暗号技術の鍵生成プロセスを可視化
3. **暗号化/復号化**: 暗号化と復号化の各ステップを段階的に表示
4. **詳細情報の表示**: 各ステップの内部処理を詳細に表示
   - データ変換の段階表示（文字列 → バイト配列 → 暗号文）
   - バイトレベルの詳細表示（16進数、10進数、2進数、ASCII）
   - 処理フローの説明
5. **MAC計算/検証**: Poly1305のMAC計算と検証機能

### 開発コマンド

```bash
# 開発サーバーの起動
npm run web:dev

# ビルド
npm run web:build

# ビルド結果のプレビュー
npm run web:preview
```

### 実装の特徴

- **デフォルトで詳細表示**: 各ステップの詳細情報がデフォルトで表示される
- **段階的な可視化**: データの変換過程を段階的に表示
- **バイトレベルの詳細**: 各バイトの詳細情報を表形式で表示
- **処理フローの説明**: 各ステップで何が起こっているかを説明

## テスト

- 各サンプルコードには、基本的な動作確認のためのテストを含める
- **テストフレームワーク**: Vitest

## コミットメッセージのフォーマット

コミットメッセージは以下のいずれかの形式をPrefixとして使用してください:

- `feat`: 新機能の追加
- `fix`: バグ修正
- `docs`: ドキュメントのみの変更
- `style`: コードの意味に影響しない変更（空白、フォーマット、セミコロンの追加など）
- `refactor`: バグ修正でも新機能追加でもないコード変更
- `perf`: パフォーマンス改善のためのコード変更
- `test`: 不足しているテストの追加や既存のテストの修正
- `chore`: ビルドプロセスや補助ツール、ライブラリの変更（ドキュメント生成など）

## 注意事項

- 実装例は教育目的であり、本番環境で使用する場合は十分な検証が必要
- セキュリティクリティカルな実装では、専門家のレビューを推奨
- 暗号学的に安全な乱数生成器を使用する
- 鍵管理のベストプラクティスに従う

## 作業フロー

1. 新しい暗号技術のサンプルを追加する際は、適切なディレクトリに配置
2. サンプルコードとテストを作成
3. 必要に応じてドキュメントを更新
4. コードレビューとテストを実施
5. **コミット前に必ずリンター・フォーマッター（biome）を実行し、エラーがないことを確認する**

