# SPHINCS+ 実装の調査結果

## 調査目的

SPHINCS+の実装が可能かどうかを調査する。特に、WebAssembly環境での動作を重視する。

## 調査結果

### 1. 利用可能なRustクレート

#### 1.1 pqcrypto-sphincsplus

**クレート情報:**
- **バージョン**: 0.7.2
- **ライセンス**: MIT OR Apache-2.0
- **リポジトリ**: https://github.com/rustpq/pqcrypto/

**特徴:**
- PQCleanプロジェクトのC実装へのバインディング
- `no_std`対応をサポート
- 複数のバリアントをサポート:
  - SHA2-128f-simple, SHA2-128s-simple
  - SHA2-192f-simple, SHA2-192s-simple
  - SHA2-256f-simple, SHA2-256s-simple
  - SHAKE-128f-simple, SHAKE-128s-simple
  - SHAKE-192f-simple, SHAKE-192s-simple
  - SHAKE-256f-simple, SHAKE-256s-simple

**問題点:**
- Cコードへの依存（`pqcrypto-internals`）
- `getrandom` 0.3に依存（Wasm環境でのビルドが困難）
- `wasm32-unknown-unknown`ターゲットでのビルドエラー

#### 1.2 pqc_sphincsplus

**クレート情報:**
- **バージョン**: 0.2.0
- **ライセンス**: MIT OR Apache-2.0
- **リポジトリ**: https://github.com/Argyle-Software/pqc_sphincsplus

**特徴:**
- 純Rust実装
- 複数のバリアントをサポート（f128, f192, f256, s128, s192, s256）
- SHA2、SHAKE、Harakaハッシュ関数をサポート

**問題点:**
- **nightly Rustが必要**（`generic_const_exprs`機能を使用）
- stable Rustではコンパイル不可

#### 1.3 sphincs-plus-cry4

**調査結果:**
- crates.ioでの存在を確認中

### 2. WebAssembly対応の課題

**主な課題:**
1. **Cコード依存**: `pqcrypto-sphincsplus`はCコードを含むため、Wasmビルド時にCコンパイラが必要
2. **getrandomバージョン**: `getrandom` 0.3への依存がWasm環境でのビルドを困難にしている
3. **nightly Rust要件**: 純Rust実装（`pqc_sphincsplus`）はnightly Rustが必要

### 3. 実装テスト結果

**pqcrypto-sphincsplusでの試行:**
- ✅ `cargo check`: 成功（`std`環境）
- ❌ `wasm-pack build --target web`: 失敗
  - エラー: `getrandom` 0.3が`wasm32-unknown-unknown`をサポートしていない
  - Cコードのコンパイルエラーも発生する可能性

**pqc_sphincsplusでの試行:**
- ❌ `cargo check`: 失敗
  - エラー: `generic_const_exprs`機能がstable Rustでは使用できない

### 4. 結論

現時点では、**SPHINCS+のWasm実装は困難**です。理由：

1. **pqcrypto-sphincsplus**: Cコード依存と`getrandom` 0.3の問題
2. **pqc_sphincsplus**: nightly Rustが必要
3. **その他の純Rust実装**: 確認できていない

### 5. 推奨される次のステップ

1. **nightly Rustの使用を検討**: `pqc_sphincsplus`を使用する場合、nightly Rustが必要
2. **代替実装の調査**: 他の純Rust実装ライブラリの調査
3. **一時的な回避策**: SPHINCS+の実装を後回しにし、他のアルゴリズムの実装を優先

#### 1.3 sphincs-plus-cry4

**クレート情報:**
- **バージョン**: 0.1.1
- **ライセンス**: MIT
- **リポジトリ**: https://github.com/CRY4-Hash-Based-Signatures/SPHINCS-PLUS

**特徴:**
- 純Rust実装
- 複数のバリアントをサポート（128f, 128s, 192f, 192s, 256f, 256s）
- SHA2、SHAKE、BLAKEハッシュ関数をサポート
- stable Rustで動作

**問題点:**
- **シリアライズ/デシリアライズ機能が提供されていない**
- `SpxPK`、`SpxSK`、`SpxSig`のフィールドがプライベート
- Wasm環境での使用を想定していない設計
- 署名のシリアライズが複雑（`sig_fors`と`sig_ht`の構造が複雑）

**調査結果:**
- `SpxPK`は`pk_seed`と`pk_root`の2つの`Vec<u8>`フィールドを持つ
- `SpxSK`は`sk_seed`、`sk_prf`、`pk`（`SpxPK`）を持つ
- `SpxSig`は`randomness`、`sig_fors`、`sig_ht`を持つが、すべてプライベート
- `to_bytes()`や`from_bytes()`メソッドが存在しない
- 手動でシリアライズ/デシリアライズを実装する必要があるが、`SpxSig`の構造が複雑で困難

### 6. 現時点での判断

SPHINCS+の実装は、以下のいずれかの条件が満たされるまで**保留**とすることを推奨します：

1. `pqc_sphincsplus`がstable Rustをサポートする
2. `pqcrypto-sphincsplus`がWasm環境でのビルドをサポートする
3. `sphincs-plus-cry4`がシリアライズ/デシリアライズ機能を提供する、またはWasm環境での使用を想定したAPIを提供する
4. 他の純Rust実装ライブラリが利用可能になる

## 参考情報

- [pqcrypto-sphincsplus - crates.io](https://crates.io/crates/pqcrypto-sphincsplus)
- [pqc_sphincsplus - crates.io](https://crates.io/crates/pqc_sphincsplus)
- [SPHINCS+ - NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)

