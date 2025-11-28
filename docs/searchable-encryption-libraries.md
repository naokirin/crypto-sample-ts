# 検索可能暗号実装用ライブラリ選定（ブラウザ対応）

このドキュメントは、ブラウザ環境で動作するTypeScriptプロジェクトにおいて、検索可能暗号（Searchable Encryption）を実装するための推奨ライブラリと実装方法をまとめています。

## 1. 検索可能暗号の概要

検索可能暗号は、暗号化されたデータに対して直接検索を行うことを可能にする暗号技術です。主な種類として以下があります：

### 1.1 検索可能対称暗号（SSE: Searchable Symmetric Encryption）

- **概要**: 対称鍵を使用してデータを暗号化し、暗号化されたデータに対してキーワード検索を可能にする
- **特徴**: 計算効率が高く、実装が比較的容易
- **用途**: 個人が管理する暗号化データの検索

### 1.2 公開鍵検索可能暗号（PEKS: Public Key Encryption with Keyword Search）

- **概要**: 公開鍵暗号を使用し、公開鍵で暗号化されたデータに対して検索トークンを使用して検索を可能にする
- **特徴**: 送信者が受信者の公開鍵で暗号化し、受信者が検索トークンを生成
- **用途**: メールサーバーなどでの暗号化メールの検索

### 1.3 属性ベース検索可能暗号（ABSE: Attribute-Based Searchable Encryption）

- **概要**: 属性ベース暗号と検索可能暗号を組み合わせた技術
- **特徴**: 属性に基づいたアクセス制御と検索機能を提供
- **用途**: クラウドストレージでの細かいアクセス制御と検索

## 2. 実装方法の選定

### 現状の課題

ブラウザ環境で直接動作するTypeScript対応の検索可能暗号ライブラリは現時点で限られています。検索可能暗号は比較的新しい暗号技術であり、実装が複雑なため、ブラウザ環境での実装には特別なアプローチが必要です。

### 推奨アプローチ

#### アプローチ1: 純粋なJavaScript/TypeScript実装（推奨）

検索可能対称暗号（SSE）は、比較的シンプルな実装が可能です。既存の暗号プリミティブ（AES、ハッシュ関数など）を組み合わせて実装できます。

**メリット:**
- 追加のビルドステップが不要
- デバッグが容易
- ブラウザとの統合が簡単
- 依存関係が少ない

**デメリット:**
- 実装の複雑さはアルゴリズムによって異なる
- パフォーマンスはWasmより劣る可能性がある

#### アプローチ2: WebAssembly（Wasm）の活用

C/C++/Rustで実装された検索可能暗号ライブラリをWasmにコンパイルし、ブラウザ上で動作させる方法。

**メリット:**
- 既存の成熟したライブラリを活用可能
- ネイティブに近いパフォーマンス
- セキュリティが検証された実装を利用可能

**デメリット:**
- Wasmへのコンパイル作業が必要
- ビルドサイズが大きくなる可能性
- デバッグがやや複雑

## 3. 利用可能なライブラリ・システム

### 3.1 ESKS（Encrypted System with Keyword Search）

**概要:**
- 国立研究開発法人情報通信研究機構（NICT）が開発した検索可能暗号システム
- ブラウザ経由で利用可能
- デモシステム: https://searchableenc.nict.go.jp/

**特徴:**
- 特別なアプリケーションの導入不要
- テキストファイル、PDF、Microsoft Word、Excelなどのファイル形式に対応
- 複数のデバイスから同一アカウントでアクセス可能
- ユーザーがパスワードのみで任意のデバイスからログイン可能

**実装状況:**
- デモシステムとして公開されているが、ライブラリとしての配布状況は不明
- ソースコードの公開状況を確認する必要がある

**参考情報:**
- [ESKS公式サイト](https://searchableenc.nict.go.jp/)
- [NICTセキュアデータ利活用技術](https://sfl.nict.go.jp/interview/secure-data-utilization.html)

### 3.2 MongoDB Queryable Encryption

**概要:**
- MongoDBが提供する検索可能暗号機能
- ベータ版として提供開始

**特徴:**
- 暗号化されたデータに対して直接検索が可能
- サーバーサイドでの実装が主
- クライアント側のSDKも提供されている可能性

**実装状況:**
- サーバーサイドが主な用途
- ブラウザ環境での直接利用は想定されていない可能性が高い

**参考情報:**
- [MongoDB Queryable Encryption](https://www.mongodb.com/docs/manual/core/queryable-encryption/)

### 3.3 AWS DynamoDB 検索可能暗号化

**概要:**
- Amazon Web Services（AWS）が提供するDynamoDB向けの検索可能暗号化機能
- AWS Database Encryption SDKを使用

**特徴:**
- 暗号化されたデータに対して検索操作が可能
- AWSのマネージドサービスとして提供

**実装状況:**
- AWS SDKを使用する必要がある
- ブラウザ環境での直接利用は限定的

**参考情報:**
- [AWS Database Encryption SDK - DynamoDB検索可能暗号化](https://docs.aws.amazon.com/ja_jp/database-encryption-sdk/latest/devguide/ddb-searchable-encryption.html)

### 3.4 OpenFHE（準同型暗号）

**概要:**
- 準同型暗号のライブラリ
- WebAssembly化することでブラウザ上での実行が可能

**特徴:**
- 準同型暗号により、暗号化されたデータに対して計算が可能
- 検索可能暗号の実装に準同型暗号を活用できる可能性がある
- C++で実装されており、Wasmにコンパイル可能

**実装状況:**
- Wasm化の取り組みが進められている
- 実装例やチュートリアルを確認する必要がある

**参考情報:**
- [OpenFHE公式サイト](https://www.openfhe.org/)
- [OpenFHE GitHub](https://github.com/openfheorg/openfhe)

### 3.5 WISE Encrypt

**概要:**
- 検索可能およびソート可能な暗号化をサポートするライブラリ
- CまたはJavaのライブラリとして提供

**特徴:**
- クラウド暗号化システムの開発に使用可能
- 検索可能暗号とソート可能暗号の両方をサポート

**実装状況:**
- CまたはJavaのライブラリ
- ブラウザ環境での直接利用にはWasm化が必要

**参考情報:**
- [WISE Encrypt](https://happylibus.com/doc/186895/)

## 4. 実装推奨事項

### 4.1 検索可能対称暗号（SSE）の実装

**推奨アプローチ: 純粋なTypeScript実装**

検索可能対称暗号は、既存の暗号プリミティブを組み合わせて実装可能です。

**必要な暗号プリミティブ:**
- AES（対称鍵暗号）
- SHA-256、SHA-512（ハッシュ関数）
- HMAC（メッセージ認証コード）

**実装の基本構造:**
1. **鍵生成**: マスター鍵から検索用の鍵を生成
2. **インデックス生成**: キーワードから検索可能なインデックスを生成
3. **暗号化**: データを暗号化し、インデックスと関連付け
4. **検索トークン生成**: キーワードから検索トークンを生成
5. **検索**: 検索トークンを使用して暗号化されたインデックスを検索

**参考アルゴリズム:**
- **SWP（Song, Wagner, Perrig）スキーム**: 基本的なSSEスキーム
- **SSE-1、SSE-2**: Curtmolaらの提案したSSEスキーム
- **OXT（Oblivious Cross-Tags）**: より効率的なSSEスキーム

**実装ファイル（推奨）:**
- `src/searchable/sse.ts`: 検索可能対称暗号の実装
- `tests/searchable/sse.test.ts`: テストファイル

### 4.2 公開鍵検索可能暗号（PEKS）の実装

**推奨アプローチ: WebAssembly（Wasm）の活用**

PEKSはペアリングベースの暗号技術を使用する場合が多く、実装が複雑です。

**必要な暗号プリミティブ:**
- 楕円曲線暗号（ECC）
- ペアリング演算
- ハッシュ関数

**参考ライブラリ:**
- **PBC（Pairing-Based Cryptography）ライブラリ**: ペアリング演算の基盤ライブラリ
- **MIRACLライブラリ**: 多様な暗号アルゴリズムをサポート
- **OpenABE**: 属性ベース暗号を含む多様な暗号アルゴリズム

**実装の基本構造:**
1. **鍵生成**: 公開鍵と秘密鍵のペアを生成
2. **暗号化**: 公開鍵とキーワードを使用して暗号文を生成
3. **検索トークン生成**: 秘密鍵とキーワードから検索トークンを生成
4. **検索**: 検索トークンを使用して暗号文を検索

**実装ファイル（推奨）:**
- `src/searchable/peks.ts`: 公開鍵検索可能暗号の実装
- `tests/searchable/peks.test.ts`: テストファイル

### 4.3 属性ベース検索可能暗号（ABSE）の実装

**推奨アプローチ: WebAssembly（Wasm）の活用**

ABSEは属性ベース暗号と検索可能暗号を組み合わせた技術であり、実装が最も複雑です。

**必要な暗号プリミティブ:**
- 楕円曲線暗号（ECC）
- ペアリング演算
- 属性ベース暗号（ABE）

**参考ライブラリ:**
- **OpenABE**: 属性ベース暗号を含む多様な暗号アルゴリズム
- **CP-ABE実装**: Ciphertext-Policy Attribute-Based Encryptionの実装

**実装の基本構造:**
1. **セットアップ**: マスター鍵と公開パラメータを生成
2. **鍵生成**: 属性に基づいて秘密鍵を生成
3. **暗号化**: アクセスポリシーとキーワードを使用して暗号化
4. **検索トークン生成**: 属性とキーワードから検索トークンを生成
5. **検索**: 検索トークンを使用して暗号文を検索

**実装ファイル（推奨）:**
- `src/searchable/abse.ts`: 属性ベース検索可能暗号の実装
- `tests/searchable/abse.test.ts`: テストファイル

## 5. 実装の優先順位

### フェーズ1: 検索可能対称暗号（SSE）の実装（推奨）

**理由:**
- 実装が比較的容易
- 既存の暗号プリミティブ（AES、ハッシュ関数）を活用可能
- 純粋なTypeScriptで実装可能
- 実用的な用途が多い

**実装するアルゴリズム:**
- SWP（Song, Wagner, Perrig）スキーム: 基本的なSSEスキーム
- SSE-1、SSE-2: より効率的なSSEスキーム

### フェーズ2: 公開鍵検索可能暗号（PEKS）の実装

**理由:**
- 実装が複雑だが、Wasm化により実現可能
- メールサーバーなどでの実用的な用途がある

**実装方法:**
- PBCライブラリまたはMIRACLライブラリをWasm化
- または、既存のIBE実装を拡張

### フェーズ3: 属性ベース検索可能暗号（ABSE）の実装

**理由:**
- 実装が最も複雑
- 属性ベース暗号（ABE）の実装が前提となる
- 実用的な用途は限定的

**実装方法:**
- OpenABEをWasm化
- または、既存のABE実装を拡張

## 6. 参考資料

### 学術論文

1. **Song, D. X., Wagner, D., & Perrig, A. (2000).** "Practical techniques for searches on encrypted data." IEEE Symposium on Security and Privacy.

2. **Curtmola, R., Garay, J., Kamara, S., & Ostrovsky, R. (2006).** "Searchable symmetric encryption: improved definitions and efficient constructions." ACM Conference on Computer and Communications Security.

3. **Boneh, D., Di Crescenzo, G., Ostrovsky, R., & Persiano, G. (2004).** "Public key encryption with keyword search." EUROCRYPT.

### 実装リソース

- [NICT ESKS](https://searchableenc.nict.go.jp/): 検索可能暗号のデモシステム
- [OpenFHE](https://www.openfhe.org/): 準同型暗号ライブラリ
- [OpenABE](https://github.com/zeutro/openabe): 属性ベース暗号ライブラリ

## 7. まとめ

ブラウザ環境で動作する検索可能暗号のライブラリは現時点で限られていますが、以下のアプローチで実装が可能です：

1. **検索可能対称暗号（SSE）**: 純粋なTypeScriptで実装可能（推奨）
2. **公開鍵検索可能暗号（PEKS）**: Wasm化により実装可能
3. **属性ベース検索可能暗号（ABSE）**: Wasm化により実装可能（最も複雑）

まずは検索可能対称暗号（SSE）の実装から開始することを推奨します。

