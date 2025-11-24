# IBE実装の進捗状況

## 現在の状況

基本的な構造は完成しましたが、Miracl CoreのAPIを使用した実際のIBE実装はまだ未完成です。

## 実装が必要な項目

### 1. Setup（マスター鍵ペアの生成）

Boneh-Franklin IBEスキームのSetupアルゴリズム:
1. マスター秘密鍵sをランダムに選択
2. 公開パラメータP_pub = sPを計算（Pは生成元）
3. マスター鍵と公開パラメータを返す

**必要なMiracl Core API:**
- ランダムなBIGの生成
- 楕円曲線上の点のスカラー倍算
- バイト列への変換

### 2. Extract（アイデンティティから秘密鍵を抽出）

Boneh-Franklin IBEスキームのExtractアルゴリズム:
1. アイデンティティIDをハッシュ化してH(ID)を計算
2. 秘密鍵d_ID = sH(ID)を計算
3. 秘密鍵を返す

**必要なMiracl Core API:**
- ハッシュ関数（SHA-256など）
- 楕円曲線上の点のスカラー倍算
- バイト列への変換

### 3. Encrypt（メッセージの暗号化）

Boneh-Franklin IBEスキームのEncryptアルゴリズム:
1. ランダムなrを選択
2. U = rPを計算
3. V = M ⊕ H(e(P_pub, H(ID))^r)を計算
4. 暗号文C = (U, V)を返す

**必要なMiracl Core API:**
- ペアリング演算 e(·, ·)
- 楕円曲線上の点のスカラー倍算
- ハッシュ関数
- XOR演算

### 4. Decrypt（暗号文の復号化）

Boneh-Franklin IBEスキームのDecryptアルゴリズム:
1. 暗号文C = (U, V)を解析
2. e(d_ID, U)を計算
3. M = V ⊕ H(e(d_ID, U))を計算
4. メッセージMを返す

**必要なMiracl Core API:**
- ペアリング演算 e(·, ·)
- ハッシュ関数
- XOR演算

## 次のステップ

1. Miracl CoreのAPIドキュメントを確認
2. 基本的なペアリング演算のテストコードを作成
3. 各アルゴリズムを段階的に実装
4. テストとデバッグ

## 参考資料

- [Boneh-Franklin IBE論文](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf)
- [Miracl Core GitHub](https://github.com/miracl/core)
- [Miracl Core Rustドキュメント](https://docs.rs/miracl_core/2.7.0)

