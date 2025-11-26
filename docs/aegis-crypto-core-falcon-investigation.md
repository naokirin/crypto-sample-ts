# aegis-crypto-core によるFALCON実装の調査結果

## 調査目的

`aegis-crypto-core`を使用してFALCONの実装が可能かどうかを調査する。

## 調査結果

### 1. aegis-crypto-coreの概要

`aegis-crypto-core`は、Rust、WebAssembly、Python、Node.js向けに設計されたポスト量子暗号ライブラリです。

**サポートされているアルゴリズム:**
- **ML-KEM**: ML-KEM-512、ML-KEM-768、ML-KEM-1024
- **ML-DSA**: ML-DSA-44、ML-DSA-65、ML-DSA-87
- **SLH-DSA**: SLH-DSA-SHA2-128f、SLH-DSA-SHA2-192f、SLH-DSA-SHA2-256f、SLH-DSA-SHAKE-128f、SLH-DSA-SHAKE-192f、SLH-DSA-SHAKE-256f
- **FN-DSA**: FN-DSA-512、FN-DSA-1024（FALCONのNIST標準名）
- **HQC-KEM**: HQC-KEM-128、HQC-KEM-192、HQC-KEM-256
- **Classic McEliece**: 348864、460896、6688128（実験的でデフォルトでは無効）

### 2. FALCON（FN-DSA）のサポート状況

`aegis-crypto-core`は**FN-DSA（FALCON）をサポート**しており、以下のバリアントが利用可能です：
- **FN-DSA-512**: FALCON-512相当
- **FN-DSA-1024**: FALCON-1024相当

### 3. WebAssembly対応

`aegis-crypto-core`はWebAssembly（Wasm）をサポートしており、`wasm32-unknown-unknown`ターゲットでのビルドが可能です。これにより、ブラウザ環境での動作が期待できます。

### 4. 現在の状況

**npmパッケージの状態:**
- `aegis-crypto-core`はnpmパッケージとして存在していたが、2025年9月29日に公開停止（Unpublished）された
- 現在はnpmレジストリから直接インストールできない

**Rustクレートとしての利用:**
- crates.ioには`aegis-crypto-core`という名前のクレートは存在しない
- GitHubリポジトリの特定が必要

### 5. 実装上の注意点

FALCONの署名プロセスは以下の特性を持ちます：
- **浮動小数点演算**: 高精度な浮動小数点演算が必要
- **高速フーリエ変換（FFT）**: FFTアルゴリズムに依存
- **数値精度**: 純粋な整数演算を使用する他のスキームと比較して、実装が複雑

WebAssembly環境での実装には、浮動小数点演算の精度やパフォーマンスに注意が必要です。

### 6. 次のステップ

1. **GitHubリポジトリの特定**: `aegis-crypto-core`のGitHubリポジトリを特定し、ソースコードを確認
2. **Rustクレートとしての利用方法**: Git依存として直接使用できるか確認
3. **wasm-packでのビルドテスト**: 実際にwasm-packでビルドできるかテスト
4. **APIの確認**: FALCON（FN-DSA）のAPIが`pqcrypto-falcon`と同様に使用できるか確認

### 7. 推奨事項

`aegis-crypto-core`を使用してFALCONを実装することは**技術的に可能**であると考えられますが、以下の点を確認する必要があります：

1. **リポジトリのアクセス**: GitHubリポジトリが公開されているか、またはGit依存として使用できるか
2. **ライセンス**: ライセンスがプロジェクトの要件に適合するか
3. **メンテナンス状況**: ライブラリが積極的にメンテナンスされているか
4. **Wasmビルドの確認**: 実際に`wasm32-unknown-unknown`ターゲットでビルドできるか

## 注意: 名前の混乱

検索結果から、以下の2つの異なるライブラリが存在することが判明しました：

1. **`aegis` Rustクレート**: AEGISファミリーの認証暗号アルゴリズムの実装。FALCONとは無関係。
2. **`aegis-crypto-core`**: ポスト量子暗号ライブラリとして言及されているが、具体的なGitHubリポジトリの特定が必要。

## 結論

`aegis-crypto-core`はFALCON（FN-DSA）をサポートしており、WebAssembly環境での使用も可能であると**報告されています**が、以下の課題があります：

1. **npmパッケージ**: 2025年9月29日に公開停止（Unpublished）
2. **Rustクレート**: crates.ioには存在しない
3. **GitHubリポジトリ**: 具体的なリポジトリURLが特定できていない

## 推奨される次のステップ

1. **GitHubリポジトリの特定**: 
   - `aegis-crypto-core`の正確なGitHubリポジトリURLを特定
   - リポジトリが公開されているか確認
   - ライセンスとメンテナンス状況を確認

2. **代替案の検討**:
   - `falcon-rust`クレート（非公式だが純Rust実装）
   - `pqcrypto-falcon`のWasm対応版の開発状況を確認
   - 他のFALCON実装ライブラリの調査

3. **実装テスト**:
   - リポジトリが特定できた場合、Git依存として追加
   - `wasm32-unknown-unknown`ターゲットでのビルドテスト
   - APIの互換性確認

## 現時点での判断

`aegis-crypto-core`を使用したFALCON実装は**理論的には可能**ですが、**実用的には困難**です。理由：

- リポジトリの特定ができていない
- npmパッケージが公開停止されている
- 具体的な使用方法が不明

**推奨**: まずはGitHubリポジトリの正確なURLを特定し、実際にアクセス可能か確認してから実装を進めることを推奨します。

