# GitHub Pages へのデプロイ手順

このドキュメントでは、`crypto-sample-ts`プロジェクトをGitHub Pagesに手動でデプロイする手順を説明します。

## 前提条件

- Node.jsとnpmがインストールされていること
- プロジェクトの依存関係がインストールされていること（`npm install`を実行済み）

## デプロイ手順

### 1. ビルドの実行

プロジェクトルートで以下のコマンドを実行して、Webアプリケーションをビルドします：

```bash
npm run web:build
```

このコマンドは`dist-web/`ディレクトリにビルド結果を出力します。

### 2. GitHub Pagesの設定

GitHubリポジトリのSettings > Pagesにアクセスし、以下のいずれかの方法で設定します：

#### 方法A: `dist-web`ディレクトリを直接使用（推奨）

1. Settings > Pages > Source で「Deploy from a branch」を選択
2. Branch: `main`（または`master`）を選択
3. Folder: `/dist-web`を選択
4. Saveをクリック

**注意**: この方法を使用する場合、`dist-web/`ディレクトリをGitにコミットする必要があります（通常は`.gitignore`に含まれているため、一時的に除外するか、別の方法を使用してください）。

#### 方法B: `docs`ディレクトリを使用

1. `dist-web/`の内容を`docs/`ディレクトリにコピー：

```bash
cp -r dist-web/* docs/
```

2. `docs/`ディレクトリをGitにコミット・プッシュ：

```bash
git add docs/
git commit -m "docs: add GitHub Pages deployment files"
git push
```

3. Settings > Pages > Source で「Deploy from a branch」を選択
4. Branch: `main`（または`master`）を選択
5. Folder: `/docs`を選択
6. Saveをクリック

#### 方法C: `gh-pages`ブランチを使用

1. `gh-pages`ブランチを作成・チェックアウト：

```bash
git checkout -b gh-pages
```

2. `dist-web/`の内容をルートにコピー：

```bash
cp -r dist-web/* .
```

3. 変更をコミット・プッシュ：

```bash
git add .
git commit -m "docs: deploy to GitHub Pages"
git push origin gh-pages
```

4. Settings > Pages > Source で「Deploy from a branch」を選択
5. Branch: `gh-pages`を選択
6. Folder: `/ (root)`を選択
7. Saveをクリック

### 3. Baseパスの設定

現在、`vite.config.ts`では`base: './'`（相対パス）が設定されています。これにより、GitHub Pagesの任意のパス（`/crypto-sample-ts`など）に配置しても、アセットファイルが正しく読み込まれます。

#### 現在の設定

```typescript
import { defineConfig } from "vite";

export default defineConfig({
  base: "./", // 相対パスで出力（GitHub Pagesの任意のパスで動作）
  build: {
    outDir: "dist-web",
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    open: true,
  },
  assetsInclude: ["**/*.wasm"],
});
```

この設定により、ビルド後のHTMLでは`./assets/index-*.js`のような相対パスでアセットが参照されます。そのため、リポジトリ名がURLに含まれる場合（`https://username.github.io/repository-name/`）でも、含まれない場合（`https://username.github.io/`）でも、どちらでも正しく動作します。

#### 他の設定方法（参考）

もし特定のパスに固定したい場合は、以下のように設定することもできます：

```typescript
base: '/repository-name/', // リポジトリ名に置き換える
```

ただし、相対パス（`base: './'`）を使用することで、より柔軟にデプロイできるため、現在の設定を推奨します。

## 配置するファイル・ディレクトリ

GitHub Pagesに配置する必要があるのは、`dist-web/`ディレクトリの内容全体です：

```
dist-web/
├── index.html          # メインのHTMLファイル
└── assets/             # ビルドされたJavaScript、WASMファイルなど
    ├── index-*.js      # メインのJavaScriptバンドル
    ├── *_wasm_bg-*.wasm  # WebAssemblyファイル
    └── *_wasm-*.js     # WebAssemblyのラッパーJavaScript
```

**重要**: `dist-web/`ディレクトリ全体を配置してください。`assets/`ディレクトリ内のファイルは、ビルド時にハッシュ付きのファイル名で生成されるため、すべて必要です。

## デプロイ後の確認

1. GitHub PagesのURL（通常は`https://username.github.io/repository-name/`）にアクセス
2. ページが正しく表示されることを確認
3. 各暗号技術の機能が正常に動作することを確認
4. ブラウザの開発者ツールでエラーがないか確認

## トラブルシューティング

### 404エラーが発生する

- すべてのファイルが正しく配置されているか確認
- `vite.config.ts`の`base`オプションが`'./'`（相対パス）に設定されているか確認
- ブラウザの開発者ツールのNetworkタブで、どのファイルが404エラーになっているか確認

### アセット（JavaScript、WASMファイル）が読み込まれない

- `assets/`ディレクトリが正しく配置されているか確認
- ブラウザの開発者ツールのNetworkタブで、どのファイルが404エラーになっているか確認
- ビルド後のHTMLでアセットのパスが相対パス（`./assets/...`）になっているか確認
- `vite.config.ts`の`base`オプションが`'./'`に設定されていることを確認

### ビルド後のファイルが古い

- `npm run web:build`を再実行
- ブラウザのキャッシュをクリア

## 更新手順

コードを更新した後、GitHub Pagesを更新するには：

1. 変更をコミット・プッシュ
2. ビルドを再実行：`npm run web:build`
3. 選択した方法（方法A/B/C）に応じて、ビルド結果を配置
4. 変更をコミット・プッシュ（方法B/Cの場合）

GitHub Pagesは自動的に再デプロイされます（数分かかる場合があります）。

