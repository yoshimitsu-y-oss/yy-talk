# YY-Talk v56: authenticated development branch

このブランチは、提供された v56 を基準とするセキュリティ改修の開発版です。本番には公開していません。

- [監査結果と変更計画](docs/AUDIT-ja.md)
- [会社向け設定手順](docs/SETUP-ja.md)
- [検証結果・未検証事項](docs/TESTS-ja.md)

Node.js 22 以降と Python 3 を使います。追加パッケージなしでローカル検証できます。

```sh
python3 scripts/build.py
npm run check
npm test
```

`app/v56.html` は固定管理者パスワードを取り除いた入力元、`src/client-security.js` と `scripts/build.py` がセキュリティ差分、`public/index.html` が生成物です。配信対象は `public` だけで、認証済みの Worker がルート HTML を返します。

認証や鍵が未設定の場合はアクセスを拒否します。テスト用の認証バイパスや公開プレビューはありません。マージ、デプロイ、旧公開経路の停止、鍵交換、DNS変更は別途承認が必要です。
