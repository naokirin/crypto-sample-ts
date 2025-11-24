# 非対称鍵暗号実装用ライブラリ選定（ブラウザ対応）

このドキュメントは、ブラウザ環境で動作するTypeScriptプロジェクトにおいて、非対称鍵暗号（RSA、ECC、IDベース暗号、属性ベース暗号）を実装するための推奨ライブラリをまとめています。

## 1. RSA（Rivest-Shamir-Adleman）

### 推奨: `node-forge`

**理由:**
- ブラウザとNode.jsの両方で動作
- RSAの鍵生成、暗号化/復号化、署名/検証をサポート
- TypeScriptの型定義が利用可能（`@types/node-forge`）
- 実績があり、広く使用されている

**インストール:**
```bash
npm install node-forge
npm install --save-dev @types/node-forge
```

**主な機能:**
- RSA鍵ペアの生成（2048ビット、4096ビットなど）
- RSA-OAEP、RSA-PKCS1-v1_5による暗号化/復号化
- RSA署名と検証
- PEM形式での鍵のエクスポート/インポート

**代替案: Web Crypto API**
- ブラウザ標準API
- RSA-OAEPの暗号化/復号化をサポート
- ただし、鍵生成や署名機能は限定的

## 2. ECC（Elliptic Curve Cryptography）

### 推奨: `@noble/curves`

**理由:**
- ブラウザとNode.jsの両方で動作
- 既存の`@noble/ciphers`と一貫性がある
- TypeScript対応で軽量かつセキュア
- 多数の楕円曲線をサポート

**インストール:**
```bash
npm install @noble/curves
```

**サポートする楕円曲線:**
- secp256k1（Bitcoinで使用）
- P-256、P-384、P-521（NIST推奨曲線）
- Ed25519、Ed448（Edwards曲線）
- その他多数

**主な機能:**
- 秘密鍵/公開鍵の生成
- ECDH（楕円曲線Diffie-Hellman鍵交換）
- ECDSA署名と検証
- EdDSA署名と検証

**代替案: Web Crypto API**
- ブラウザ標準API
- ECDH、ECDSAをサポート
- ただし、サポートする曲線は限定的（P-256、P-384、P-521など）

## 3. IDベース暗号（Identity-Based Encryption, IBE）

### 現状の課題

ブラウザ環境で直接動作するTypeScript対応のIBEライブラリは現時点で一般的ではありません。IBEはペアリングベースの暗号技術を使用するため、実装が複雑で計算量も多いです。

### 推奨アプローチ

#### アプローチ1: WebAssembly（Wasm）の活用（推奨）

C/C++/Rustで実装されたIBEライブラリをWasmにコンパイルし、ブラウザ上で動作させる方法。

**参考ライブラリ:**

1. **OpenABE**（C/C++）
   - GitHub: https://github.com/zeutro/openabe
   - 属性ベース暗号を含む多様な暗号アルゴリズムを提供
   - Emscriptenを使用してWasmにコンパイル可能
   - 実装手順:
     - OpenABEのソースコードを取得
     - EmscriptenでWasmにコンパイル
     - TypeScriptからWasmモジュールをロードして呼び出し

2. **PBC（Pairing-Based Cryptography）ライブラリ**（C）
   - ペアリングベース暗号の基盤ライブラリ
   - IBEの実装に必要なペアリング演算を提供
   - EmscriptenでWasmにコンパイル可能
   - 参考記事: [Qiita - PBCライブラリを使用したIBE/ABEの試行](https://qiita.com/kenmaro/items/e0b56924d6fac2cf0391)

3. **TEPLAライブラリ**（C）
   - 筑波大学が開発した楕円曲線およびペアリング暗号のライブラリ
   - IBEの実装に利用可能

4. **MIRACLライブラリ**（C）
   - 多様な暗号アルゴリズムをサポート
   - IBEやABEの実装に適している

**実装手順:**
1. 適切なC/C++ライブラリを選定（推奨: OpenABEまたはPBC）
2. Emscriptenをインストール・設定
3. ライブラリをWasmにコンパイル
4. TypeScriptからWasmモジュールをロード
5. TypeScriptのラッパー関数を作成して呼び出し

**必要なツール:**
- Emscripten: C/C++をWasmにコンパイルするツールチェーン
- wasm-pack: RustをWasmにコンパイルするツール（Rust実装の場合）

#### アプローチ2: 純粋なTypeScriptによる参考実装

現時点で、完全なIBEの純粋なTypeScript実装は見つかりませんでしたが、以下のアプローチが考えられます。

**関連するTypeScriptライブラリ（参考実装）:**

1. **ecies-js**（TypeScript）
   - GitHub: https://github.com/ecies/js
   - ECIES（Elliptic Curve Integrated Encryption Scheme）の実装
   - ブラウザとNode.jsの両方で動作
   - IBEとは異なるが、楕円曲線暗号の実装例として参考になる

2. **js-ascon**（TypeScript）
   - GitHub: https://github.com/brainfoolong/js-ascon
   - 軽量な認証付き暗号の実装
   - ブラウザ環境での利用が可能
   - 暗号化の実装パターンとして参考になる

**実装アプローチ:**

1. **学術論文や技術記事の参照**
   - IBEのアルゴリズム仕様を理解
   - 数学的な定義をTypeScriptで実装
   - 参考: NTT技術ジャーナルの属性ベース暗号の解説

2. **他言語の実装の移植**
   - C++でのIBE実装例（Qiitaなど）を参考にTypeScriptに移植
   - PythonのCharm-Cryptoの実装を参考にする
   - JavaのJPBCの実装を参考にする

3. **ペアリング演算の実装**
   - IBEの基盤となるペアリング演算をTypeScriptで実装
   - 楕円曲線の演算ライブラリ（`@noble/curves`など）を活用
   - ただし、ペアリング演算は非常に複雑で計算量が多い

**注意点:**
- 純粋なTypeScript実装はパフォーマンス面で課題がある可能性
- セキュリティ面での十分な検証が必要
- 開発コストが高い

#### アプローチ3: サーバーサイド処理

ブラウザでの実装が困難な場合、IBEの処理をサーバーサイドで行い、ブラウザとはAPIを通じて通信する方法。

**メリット:**
- ブラウザ側の負荷を軽減
- 既存の成熟したライブラリを活用可能
- パフォーマンスが高い

**デメリット:**
- サーバーとの通信が必要
- プライバシーやセキュリティの考慮が必要
- レイテンシーの問題

## 4. 属性ベース暗号（Attribute-Based Encryption, ABE）

### 現状の課題

ブラウザ環境で直接動作するTypeScript対応のABEライブラリは現時点で一般的ではありません。ABEもペアリングベースの暗号技術を使用するため、実装が複雑で計算量も多いです。

### 推奨アプローチ

#### アプローチ1: WebAssembly（Wasm）の活用（推奨）

C/C++/Rustで実装されたABEライブラリをWasmにコンパイルし、ブラウザ上で動作させる方法。

**参考ライブラリ:**

1. **OpenABE**（C/C++）
   - GitHub: https://github.com/zeutro/openabe
   - 属性ベース暗号（ABE）を含む多様な暗号アルゴリズムを提供
   - CP-ABE（Ciphertext-Policy ABE）とKP-ABE（Key-Policy ABE）をサポート
   - Emscriptenを使用してWasmにコンパイル可能
   - 実装手順:
     - OpenABEのソースコードを取得
     - EmscriptenでWasmにコンパイル
     - TypeScriptからWasmモジュールをロードして呼び出し

2. **PBC（Pairing-Based Cryptography）ライブラリ**（C）
   - ペアリングベース暗号の基盤ライブラリ
   - ABEの実装に必要なペアリング演算を提供
   - EmscriptenでWasmにコンパイル可能
   - 参考記事: [Qiita - PBCライブラリを使用したIBE/ABEの試行](https://qiita.com/kenmaro/items/e0b56924d6fac2cf0391)

3. **Charm-Crypto**（Python）
   - GitHub: https://github.com/JHUISI/charm
   - Pythonで実装された暗号ライブラリ
   - ABEをサポート
   - Wasm化が検討可能（Pyodideなどを使用）

4. **JPBC**（Java）
   - Javaで実装されたペアリングベース暗号ライブラリ
   - ABEの実装例あり
   - Wasm化は困難だが、サーバーサイド処理として利用可能

**実装手順:**
1. 適切なC/C++ライブラリを選定（推奨: OpenABE）
2. Emscriptenをインストール・設定
3. ライブラリをWasmにコンパイル
4. TypeScriptからWasmモジュールをロード
5. TypeScriptのラッパー関数を作成して呼び出し

**必要なツール:**
- Emscripten: C/C++をWasmにコンパイルするツールチェーン
- wasm-pack: RustをWasmにコンパイルするツール（Rust実装の場合）

**参考情報:**
- [NTT技術ジャーナル - 属性ベース暗号の最新動向](https://journal.ntt.co.jp/article/21884)

#### アプローチ2: 純粋なTypeScriptによる参考実装

現時点で、完全なABEの純粋なTypeScript実装は見つかりませんでしたが、以下のアプローチが考えられます。

**関連するTypeScriptライブラリ（参考実装）:**

1. **ecies-js**（TypeScript）
   - GitHub: https://github.com/ecies/js
   - ECIES（Elliptic Curve Integrated Encryption Scheme）の実装
   - ブラウザとNode.jsの両方で動作
   - ABEとは異なるが、楕円曲線暗号の実装例として参考になる

2. **js-ascon**（TypeScript）
   - GitHub: https://github.com/brainfoolong/js-ascon
   - 軽量な認証付き暗号の実装
   - ブラウザ環境での利用が可能
   - 暗号化の実装パターンとして参考になる

**実装アプローチ:**

1. **学術論文や技術記事の参照**
   - ABEのアルゴリズム仕様を理解
   - 数学的な定義をTypeScriptで実装
   - 参考: NTT技術ジャーナルの属性ベース暗号の解説

2. **他言語の実装の移植**
   - C++でのABE実装例を参考にTypeScriptに移植
   - PythonのCharm-Cryptoの実装を参考にする
   - JavaのJPBCの実装を参考にする

3. **ペアリング演算の実装**
   - ABEの基盤となるペアリング演算をTypeScriptで実装
   - 楕円曲線の演算ライブラリ（`@noble/curves`など）を活用
   - ただし、ペアリング演算は非常に複雑で計算量が多い

**注意点:**
- 純粋なTypeScript実装はパフォーマンス面で課題がある可能性
- セキュリティ面での十分な検証が必要
- 開発コストが高い

#### アプローチ3: サーバーサイド処理

ブラウザでの実装が困難な場合、ABEの処理をサーバーサイドで行い、ブラウザとはAPIを通じて通信する方法。

**メリット:**
- ブラウザ側の負荷を軽減
- 既存の成熟したライブラリを活用可能
- パフォーマンスが高い

**デメリット:**
- サーバーとの通信が必要
- プライバシーやセキュリティの考慮が必要
- レイテンシーの問題

## 推奨パッケージ構成

既存の`@noble/ciphers`との一貫性を考慮した推奨構成:

```json
{
  "dependencies": {
    "@noble/ciphers": "^2.0.1",     // 既存（対称鍵暗号用）
    "@noble/curves": "^1.7.0",      // ECC用（新規追加推奨）
    "node-forge": "^1.3.1"          // RSA用（新規追加推奨）
  },
  "devDependencies": {
    "@types/node-forge": "^1.3.0"   // node-forgeの型定義
  }
}
```

## 実装方針

### RSA
- `node-forge`を使用して実装
- 鍵生成、暗号化/復号化、署名/検証のサンプルを作成

### ECC
- `@noble/curves`を使用して実装
- 主要な楕円曲線（secp256k1、P-256、Ed25519など）のサンプルを作成
- ECDH、ECDSA、EdDSAのサンプルを作成

### IDベース暗号
- **Wasmを活用した実装（推奨）**
  - OpenABEまたはPBCライブラリをWasmにコンパイル
  - TypeScriptからWasmモジュールを呼び出すラッパーを作成
  - 基本的なIBEの暗号化/復号化のサンプルを作成
- **純粋なTypeScriptによる参考実装**
  - 理論的な説明と疑似コードを提供
  - 可能であれば、簡易版の実装例を作成（教育目的）
  - ペアリング演算の簡易実装を検討
- **サーバーサイド処理の例**
  - サーバーサイドでIBE処理を行う例を提供（参考）

### 属性ベース暗号
- **Wasmを活用した実装（推奨）**
  - OpenABEライブラリをWasmにコンパイル
  - TypeScriptからWasmモジュールを呼び出すラッパーを作成
  - CP-ABEまたはKP-ABEの基本的なサンプルを作成
- **純粋なTypeScriptによる参考実装**
  - 理論的な説明と疑似コードを提供
  - 可能であれば、簡易版の実装例を作成（教育目的）
  - ペアリング演算の簡易実装を検討
- **サーバーサイド処理の例**
  - サーバーサイドでABE処理を行う例を提供（参考）

## 注意事項

1. **セキュリティ**: 実装例は教育目的であり、本番環境で使用する場合は十分な検証が必要
2. **パフォーマンス**: ブラウザ環境では、計算量の多い暗号処理がパフォーマンスに影響を与える可能性がある
3. **互換性**: ブラウザの互換性を確認（特にWebAssemblyを使用する場合）
4. **鍵管理**: 鍵管理のベストプラクティスに従う

