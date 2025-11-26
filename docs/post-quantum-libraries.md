# 耐量子暗号実装用ライブラリ選定（ブラウザ対応）

このドキュメントは、ブラウザ環境で動作するTypeScriptプロジェクトにおいて、耐量子暗号（Post-Quantum Cryptography, PQC）を実装するための推奨ライブラリと実装方法をまとめています。

## 実装状況

### ✅ CRYSTALS-Kyber (ML-KEM) - 実装完了

**実装方法**: Rust + wasm-pack
**ライブラリ**: `pqcrypto-std v0.3.1`
**実装ファイル**: 
- Rust実装: `wasm-src/kyber-wasm/src/lib.rs`
- TypeScriptラッパー: `src/post-quantum/kyber.ts`
- テスト: `tests/post-quantum/kyber.test.ts`

**詳細**: `docs/post-quantum-implementation-summary.md`を参照

## 1. 耐量子暗号の概要

耐量子暗号は、量子コンピュータによる攻撃に耐性を持つ次世代の暗号技術です。NIST（米国国立標準技術研究所）は2024年8月に以下の3つの耐量子暗号標準を発表しました：

### NIST標準選定アルゴリズム

#### 鍵交換（Key Encapsulation Mechanism, KEM）
- **CRYSTALS-Kyber**: 格子ベース暗号、推奨方式

#### デジタル署名（Digital Signature）
- **CRYSTALS-Dilithium**: 格子ベース署名、推奨方式
- **FALCON**: 格子ベース署名、コンパクトな署名サイズ
- **SPHINCS+**: ハッシュベース署名、セキュリティ証明が明確

## 2. 実装方法の選定

### 現状の課題

ブラウザ環境で直接動作するTypeScript対応の耐量子暗号ライブラリは現時点で限られています。耐量子暗号は計算量が多く、主にC言語やRustで実装されているため、ブラウザ環境での実装には特別なアプローチが必要です。

### 推奨アプローチ

#### アプローチ1: WebAssembly（Wasm）の活用（推奨）

C/C++/Rustで実装された耐量子暗号ライブラリをWasmにコンパイルし、ブラウザ上で動作させる方法。

**メリット:**
- 既存の成熟したライブラリを活用可能
- ネイティブに近いパフォーマンス
- セキュリティが検証された実装を利用可能

**デメリット:**
- Wasmへのコンパイル作業が必要
- ビルドサイズが大きくなる可能性
- デバッグがやや複雑

#### アプローチ2: 純粋なJavaScript/TypeScript実装

JavaScript/TypeScriptで直接実装する方法。

**メリット:**
- 追加のビルドステップが不要
- デバッグが容易
- ブラウザとの統合が簡単

**デメリット:**
- パフォーマンスがWasmより劣る可能性
- 実装が複雑で開発コストが高い
- セキュリティ検証が不十分な可能性

## 3. 利用可能なライブラリ

### 3.1 Open Quantum Safe（OQS）プロジェクト - liboqs

**概要:**
- NISTのPQC標準化方式および候補方式のサンプル実装を提供
- C言語で実装
- GitHub: https://github.com/open-quantum-safe/liboqs

**サポートするアルゴリズム:**
- CRYSTALS-Kyber（鍵交換）
- CRYSTALS-Dilithium（署名）
- FALCON（署名）
- SPHINCS+（署名）
- その他多数の候補アルゴリズム

**実装方法:**
1. liboqsのソースコードを取得
2. Emscriptenを使用してWasmにコンパイル
3. TypeScriptからWasmモジュールをロード
4. TypeScriptのラッパー関数を作成

**必要なツール:**
- Emscripten: C/C++をWasmにコンパイルするツールチェーン
- CMake: ビルドシステム

**参考情報:**
- [Open Quantum Safe公式サイト](https://openquantumsafe.org/)
- [NTTデータ - 耐量子暗号の動向](https://www.nttdata.com/jp/ja/trends/data-insight/2022/0808)

### 3.2 PQClean

**概要:**
- NIST PQC標準化プロジェクトのリファレンス実装
- C言語で実装
- GitHub: https://github.com/PQClean/PQClean

**特徴:**
- 各アルゴリズムが独立した実装として提供
- クリーンな実装で理解しやすい
- 教育目的にも適している

**サポートするアルゴリズム:**
- CRYSTALS-Kyber
- CRYSTALS-Dilithium
- FALCON
- SPHINCS+

**実装方法:**
liboqsと同様に、Emscriptenを使用してWasmにコンパイル可能。

### 3.3 JavaScript/TypeScript実装のライブラリ

現時点で、完全な耐量子暗号のJavaScript/TypeScript実装は限られていますが、以下のような試みがあります：

#### pqc.js（調査中）

**注意:** 現時点で確認できた具体的なnpmパッケージは限定的です。GitHub上で個人や組織が開発している実装を調査する必要があります。

**調査すべきリソース:**
- GitHub上での「post-quantum cryptography javascript」の検索
- 「pqc.js」「liboqs-js」などのキーワードで検索
- NIST PQC標準化プロジェクトの公式リポジトリ

### 3.4 Rust実装のWasm化（推奨：ビルド環境が整えやすい）

**概要:**
Rustで実装された耐量子暗号ライブラリをwasm-packを使用してWasmにコンパイルする方法。Rustのビルド環境は整えやすく、wasm-packによるWasm化も比較的簡単です。

**メリット:**
- Rustのメモリ安全性
- wasm-packによる簡単なWasm化
- TypeScriptの型定義を自動生成可能
- C/C++のビルドツール（Emscripten、CMake）が不要
- クロスプラットフォームでのビルドが容易

**デメリット:**
- Rustの学習コスト（既にRust環境がある場合は問題なし）
- 一部のライブラリはC/C++に依存している可能性

**利用可能なRust実装ライブラリ:**

#### 3.4.1 pqcrypto（推奨候補）

**概要:**
- Rustで実装された耐量子暗号ライブラリ
- NIST標準選定アルゴリズムのすべてをサポート
- 純粋なRust実装でC/C++への依存がない

**サポートするアルゴリズム:**
- ✅ CRYSTALS-Kyber（鍵交換）
- ✅ CRYSTALS-Dilithium（署名）
- ✅ FALCON（署名）
- ✅ SPHINCS+（署名）

**特徴:**
- **no_std対応**: Wasm環境での動作が可能
- **wasm-pack対応**: wasm-packでのビルドが可能
- **アルゴリズム網羅性**: NIST標準選定アルゴリズムのすべてをサポート

**Wasm対応状況:**
- ✅ `wasm32-unknown-unknown`ターゲットでのビルドが可能
- ✅ 純粋なRust実装のため、wasm-packでのビルドが容易
- ⚠️ 実際のビルドテストが必要（プロトタイプ実装で確認）

**確認が必要な項目:**
- crates.ioでのバージョンとドキュメント
- GitHubリポジトリの特定と詳細
- セキュリティ監査の有無
- メンテナンス状況

**参考情報:**
- [crates.io - pqcrypto](https://crates.io/crates/pqcrypto)（要確認）
- 詳細は `docs/post-quantum-rust-libraries-research.md` を参照

#### 3.4.2 SARE（Secure Advanced Rust Encryption）

**概要:**
- Rustで実装された次世代の暗号化システム
- PGPのような標準的な暗号化手法を提供
- DilithiumやKyberなどのポスト量子暗号アルゴリズムを統合

**特徴:**
- 古典的な暗号アルゴリズム（ECC、Diffie-Hellman）とPQCアルゴリズムの両方をサポート
- 将来的な量子コンピュータの脅威にも対応可能

**調査状況:**
- ⚠️ 具体的なGitHubリポジトリやcrates.ioでの公開状況は確認できていない
- ⚠️ さらなる調査が必要

**参考情報:**
- GitHubリポジトリを調査する必要があります
- 検索キーワード: "SARE rust encryption" "Secure Advanced Rust Encryption"

#### 3.4.2 PQCleanのRust実装

**概要:**
- PQCleanプロジェクトには、一部のアルゴリズムについてRust実装が含まれている可能性があります
- NIST標準選定アルゴリズムのクリーンな実装

**調査が必要:**
- PQCleanのGitHubリポジトリでRust実装の有無を確認
- 各アルゴリズム（Kyber、Dilithium、FALCON、SPHINCS+）のRust実装の存在を確認

#### 3.4.3 ate-crypto

**概要:**
- 量子耐性暗号を提供するWasm対応のRust製暗号ライブラリ
- MIT/Apacheライセンス

**特徴:**
- Wasm環境での動作を想定して設計
- crates.ioで公開されている可能性

**注意:**
- 具体的なアルゴリズム（Kyber、Dilithiumなど）のサポート状況を確認する必要があります

**参考情報:**
- [crates.io - ate-crypto](https://crates.io/crates/ate-crypto)

#### 3.4.4 個別アルゴリズムのRust実装

各アルゴリズムについて、個別のRust実装が存在する可能性があります：

- **kyber-rs**: CRYSTALS-KyberのRust実装（調査が必要）
- **dilithium-rs**: CRYSTALS-DilithiumのRust実装（調査が必要）
- **falcon-rs**: FALCONのRust実装（調査が必要）
- **sphincs-rs**: SPHINCS+のRust実装（調査が必要）

**調査方法:**
- crates.ioで「kyber」「dilithium」「falcon」「sphincs」などのキーワードで検索
- GitHubで「rust kyber」「rust dilithium」などのキーワードで検索

#### 3.4.5 liboqsのRustバインディング

**概要:**
- liboqs（C言語実装）のRustバインディングを作成する方法
- `bindgen`などのツールを使用してFFIバインディングを生成

**注意:**
- C/C++コードを含むため、wasm-packの使用には制約がある可能性
- `wasm32-unknown-emscripten`ターゲットの使用が必要な場合がある

**必要なツール:**
- Rust（rustc）
- wasm-pack: RustをWasmにコンパイルするツール
- bindgen: C/C++のヘッダーファイルからRustバインディングを生成するツール（liboqsバインディングの場合）

## 4. 実装方針（Rust + wasm-pack推奨）

**推奨アプローチ: Rust実装 + wasm-pack**

Rustのビルド環境が整えやすいため、Rustで実装された耐量子暗号ライブラリをwasm-packでWasm化する方法を推奨します。

### 4.1 CRYSTALS-Kyber（鍵交換）

**推奨アプローチ: Rust実装 + wasm-pack**

1. Rust実装のKyberライブラリを選定（例: kyber-rs、SARE、PQCleanのRust実装）
2. wasm-packを使用してWasmにコンパイル
3. TypeScriptラッパーを作成
4. 鍵生成、カプセル化、デカプセル化の機能を実装

**実装ファイル:**
- `src/post-quantum/kyber.ts`
- `wasm-src/kyber-wasm/`（Rustプロジェクト、wasm-packビルド用）

**テストファイル:**
- `tests/post-quantum/kyber.test.ts`

### 4.2 CRYSTALS-Dilithium（デジタル署名）

**推奨アプローチ: Rust実装 + wasm-pack**

1. Rust実装のDilithiumライブラリを選定（例: dilithium-rs、SARE、PQCleanのRust実装）
2. wasm-packを使用してWasmにコンパイル
3. TypeScriptラッパーを作成
4. 鍵生成、署名、検証の機能を実装

**実装ファイル:**
- `src/post-quantum/dilithium.ts`
- `wasm-src/dilithium-wasm/`（Rustプロジェクト、wasm-packビルド用）

**テストファイル:**
- `tests/post-quantum/dilithium.test.ts`

### 4.3 FALCON（デジタル署名）

**推奨アプローチ: Rust実装 + wasm-pack**

1. Rust実装のFALCONライブラリを選定（例: falcon-rs、PQCleanのRust実装）
2. wasm-packを使用してWasmにコンパイル
3. TypeScriptラッパーを作成
4. 鍵生成、署名、検証の機能を実装

**実装ファイル:**
- `src/post-quantum/falcon.ts`
- `wasm-src/falcon-wasm/`（Rustプロジェクト、wasm-packビルド用）

**テストファイル:**
- `tests/post-quantum/falcon.test.ts`

### 4.4 SPHINCS+（デジタル署名）

**推奨アプローチ: Rust実装 + wasm-pack**

1. Rust実装のSPHINCS+ライブラリを選定（例: sphincs-rs、PQCleanのRust実装）
2. wasm-packを使用してWasmにコンパイル
3. TypeScriptラッパーを作成
4. 鍵生成、署名、検証の機能を実装

**実装ファイル:**
- `src/post-quantum/sphincs-plus.ts`
- `wasm-src/sphincs-plus-wasm/`（Rustプロジェクト、wasm-packビルド用）

**テストファイル:**
- `tests/post-quantum/sphincs-plus.test.ts`

## 5. 実装手順（Rust + wasm-pack）

### 5.1 環境構築

```bash
# Rustのインストール（未インストールの場合）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# wasm-packのインストール
cargo install wasm-pack

# wasm32-unknown-unknownターゲットの追加
rustup target add wasm32-unknown-unknown
```

### 5.2 Rustプロジェクトの作成

```bash
# プロジェクトルートで実行
cd wasm-src
cargo new --lib kyber-wasm
cd kyber-wasm
```

### 5.3 Cargo.tomlの設定

```toml
[package]
name = "kyber-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
# 選定したKyberライブラリを追加
# 例: kyber-rs = "0.1" または適切なライブラリ

[dependencies.web-sys]
version = "0.3"
features = [
  "console",
]
```

### 5.4 Rustコードの実装例

```rust
// src/lib.rs
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_keypair() -> Vec<u8> {
    // 選定したライブラリのAPIを使用
    // 例: kyber_rs::generate_keypair()
    // 公開鍵と秘密鍵を返す
    todo!()
}

#[wasm_bindgen]
pub fn encapsulate(pk: &[u8]) -> Vec<u8> {
    // カプセル化処理
    todo!()
}

#[wasm_bindgen]
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Vec<u8> {
    // デカプセル化処理
    todo!()
}
```

### 5.5 Wasmへのビルド

```bash
# wasm-packを使用してビルド
wasm-pack build --target web --out-dir ../../dist-web/wasm/kyber

# または、TypeScriptプロジェクトに直接出力
wasm-pack build --target web --out-dir ../../src/wasm/kyber
```

### 5.6 TypeScriptラッパーの作成

```typescript
// src/post-quantum/kyber.ts
import init, {
  generate_keypair,
  encapsulate,
  decapsulate,
} from '../wasm/kyber/kyber_wasm.js';

let wasmInitialized = false;

export async function initKyber(): Promise<void> {
  if (!wasmInitialized) {
    await init();
    wasmInitialized = true;
  }
}

export async function generateKeyPair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  await initKyber();
  const keypair = generate_keypair();
  // キーペアの分割処理
  // 実装は選定したライブラリのAPIに依存
  return {
    publicKey: new Uint8Array(keypair.slice(0, 32)), // 例
    privateKey: new Uint8Array(keypair.slice(32)), // 例
  };
}

export async function encapsulateKey(
  publicKey: Uint8Array
): Promise<{
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}> {
  await initKyber();
  const result = encapsulate(publicKey);
  // 結果の分割処理
  return {
    ciphertext: new Uint8Array(result.slice(0, 32)), // 例
    sharedSecret: new Uint8Array(result.slice(32)), // 例
  };
}

export async function decapsulateKey(
  ciphertext: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  await initKyber();
  return new Uint8Array(decapsulate(ciphertext, privateKey));
}
```

### 5.7 Vite設定

既存の`vite.config.ts`にWasmサポートが含まれていることを確認：

```typescript
export default defineConfig({
  assetsInclude: ["**/*.wasm"], // 既に設定済み
});
```

### 5.8 ビルドスクリプトの追加

`package.json`にビルドスクリプトを追加：

```json
{
  "scripts": {
    "build:wasm": "cd wasm-src/kyber-wasm && wasm-pack build --target web --out-dir ../../src/wasm/kyber",
    "build:wasm:all": "npm run build:wasm && npm run build:wasm:dilithium && ..."
  }
}
```

## 5A. 代替実装手順（liboqs + Emscripten）

Rust実装が見つからない場合の代替方法：

### 5A.1 環境構築

```bash
# Emscriptenのインストール
# https://emscripten.org/docs/getting_started/downloads.html

# liboqsのクローン
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
```

### 5A.2 Wasmへのコンパイル

```bash
# Emscriptenを使用してビルド
mkdir build-emscripten
cd build-emscripten
emcmake cmake .. -DCMAKE_BUILD_TYPE=Release
emmake make
```

### 5A.3 TypeScriptラッパーの作成

```typescript
// src/post-quantum/kyber.ts の例
export async function initKyber(): Promise<void> {
  // Wasmモジュールのロード
  const wasmModule = await import('../wasm/kyber.wasm');
  // 初期化処理
}

export async function generateKeyPair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  // liboqsの関数を呼び出し
}
```

## 6. 代替アプローチ

### 6.1 サーバーサイド処理

ブラウザでの実装が困難な場合、耐量子暗号の処理をサーバーサイドで行い、ブラウザとはAPIを通じて通信する方法。

**メリット:**
- ブラウザ側の負荷を軽減
- 既存の成熟したライブラリを活用可能
- パフォーマンスが高い

**デメリット:**
- サーバーとの通信が必要
- プライバシーやセキュリティの考慮が必要
- レイテンシーの問題

### 6.2 Web Crypto APIの将来対応

現時点でWeb Crypto APIは耐量子暗号アルゴリズムをサポートしていませんが、将来的な対応が期待されます。

**参考:**
- [Web Crypto API仕様](https://www.w3.org/TR/WebCryptoAPI/)
- W3Cの標準化プロセスを注視

## 7. 実装時の注意事項

### 7.1 セキュリティ

- **タイミング攻撃への対策**: 定数時間（constant-time）での処理を確保
- **最新の脆弱性情報の確認**: 例えば、Kyberの実装における「KyberSlash」などの脆弱性に注意
- **鍵管理**: 鍵管理のベストプラクティスに従う

**参考情報:**
- [NEC - KyberSlash脆弱性について](https://jpn.nec.com/cybersecurity/intelligence/250319/index.html)

### 7.2 パフォーマンス

- 耐量子暗号アルゴリズムは計算量が多いため、ブラウザ上での実行時にパフォーマンスの低下が懸念されます
- WebAssemblyの活用により、ネイティブコードに近い速度での処理が期待できます
- 必要に応じて、Web Workerを使用してメインスレッドをブロックしない実装を検討

### 7.3 標準化動向の把握

- NISTなどの標準化団体が進めている耐量子暗号の標準化プロセスを注視
- 最新の標準化動向を把握し、実装に反映

**参考情報:**
- [NIST PQC Standardization Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [情報処理学会 - 耐量子計算機暗号標準の動向](https://www.ipsj.or.jp/dp/contents/publication/62/DP62-S07.html)

## 8. 推奨パッケージ構成

既存のプロジェクト構成との一貫性を考慮：

```json
{
  "dependencies": {
    "@noble/ciphers": "^2.0.1",     // 既存（対称鍵暗号用）
    "@noble/curves": "^2.0.1",      // 既存（ECC用）
    "node-forge": "^1.3.1"          // 既存（RSA用）
  },
  "devDependencies": {
    "@types/node": "^22.19.1",      // 既存
    "typescript": "^5.7.2",         // 既存
    "vite": "^7.2.4"                // 既存（Wasmサポート含む）
  }
}
```

**追加が必要なツール（Rust + wasm-packの場合）:**
- Rust（rustc、cargo）
- wasm-pack: `cargo install wasm-pack`
- wasm32-unknown-unknownターゲット: `rustup target add wasm32-unknown-unknown`

**追加が必要な可能性があるツール（liboqs + Emscriptenの場合）:**
- Emscripten（開発環境のみ、npmパッケージではない）
- CMake（開発環境のみ、npmパッケージではない）

## 9. 実装の優先順位

1. **CRYSTALS-Kyber**（鍵交換）- 最も重要で使用頻度が高い
2. **CRYSTALS-Dilithium**（署名）- 推奨署名方式
3. **FALCON**（署名）- コンパクトな署名サイズが必要な場合
4. **SPHINCS+**（署名）- ハッシュベース署名が必要な場合

## 10. 参考リソース

### 公式リソース
- [Open Quantum Safe公式サイト](https://openquantumsafe.org/)
- [NIST PQC Standardization Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [PQClean GitHub](https://github.com/PQClean/PQClean)

### 技術記事
- [NTTデータ - 耐量子暗号の動向](https://www.nttdata.com/jp/ja/trends/data-insight/2022/0808)
- [Qiita - 耐量子暗号の概要と標準化動向](https://qiita.com/saitomst/items/bc8ee7820d044898d271)

### セキュリティ情報
- [NEC - KyberSlash脆弱性について](https://jpn.nec.com/cybersecurity/intelligence/250319/index.html)

## 11. 調査結果と次のステップ

### 11.1 調査結果サマリー

詳細な調査結果は `docs/post-quantum-rust-libraries-research.md` にまとめています。

**主要な発見:**
- **pqcryptoクレート**が最も有望な候補として浮上
  - ✅ NIST標準選定アルゴリズムのすべてをサポート（Kyber、Dilithium、FALCON、SPHINCS+）
  - ✅ 純粋なRust実装でwasm-pack対応が可能
  - ✅ no_std環境での動作をサポート
  - ⚠️ 具体的なGitHubリポジトリとバージョン情報の確認が必要

### 11.2 即座に実施すべき調査

1. **pqcryptoクレートの詳細確認**: 
   - [crates.io - pqcrypto](https://crates.io/crates/pqcrypto) でバージョンとドキュメントを確認
   - GitHubリポジトリを特定して詳細を調査
   - 実際のAPIと使用方法を確認

2. **実際のビルドテスト**: 
   - 最小限のプロトタイプを作成
   - wasm-packでのビルドを試行
   - エラーがあれば対処方法を調査

3. **代替案の調査**: 
   - 個別アルゴリズムの実装が存在するか再調査
   - 他のRust実装ライブラリの存在確認

### 11.3 実装フェーズ

#### フェーズ1: 検証とプロトタイプ

1. **pqcryptoクレートの詳細確認**
   - crates.ioでのバージョンとドキュメント確認
   - GitHubリポジトリの特定と調査
   - サンプルコードの確認

2. **プロトタイプ実装**
   - CRYSTALS-Kyberから開始
   - wasm-packでのビルドテスト
   - ブラウザ上での動作確認

3. **パフォーマンステスト**
   - 鍵生成時間の測定
   - 暗号化/復号化時間の測定
   - メモリ使用量の測定

#### フェーズ2: 実装と統合

1. **全アルゴリズムの実装**
   - Kyber（鍵交換）
   - Dilithium（署名）
   - FALCON（署名）
   - SPHINCS+（署名）

2. **TypeScriptラッパーの作成**
   - 統一されたAPI設計
   - エラーハンドリング
   - 型定義の提供

3. **テストとドキュメント**
   - 公式テストベクターとの互換性確認
   - 統合テスト
   - ドキュメントの作成

### 11.4 長期的な検討事項

1. **セキュリティ監査**
   - 実装のセキュリティレビュー
   - タイミング攻撃への対策確認

2. **パフォーマンス最適化**
   - Wasm環境での最適化
   - メモリ使用量の最適化

3. **メンテナンス計画**
   - ライブラリの更新頻度
   - セキュリティパッチの適用方法

