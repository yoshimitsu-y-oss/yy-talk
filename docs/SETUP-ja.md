# t-max.co.jp向けの開発環境設定手順

この手順はまだ実行していません。会社のGoogle Workspace管理者とCloudflare管理者の作業が必要です。パスワードや秘密鍵をチャット・GitHub・PRへ貼らないでください。

## 先に決めること

- 社員の会社メール: `@t-max.co.jp`（確認済み）。ドメイン名だけで社員判定はしません。
- 管理者にする人: 未定。管理者リストを空にすると、社員として参加できても管理操作はできません。
- 開発用のURLとROOM名: 未定。本番と別のホスト・Workerを使います。
- 同じLiveKit Cloudプロジェクトを使用する場合、開発通信も料金・クォータに影響します。本番ROOM名とは別の名前空間を生成します。

## Googleの担当者に依頼すること

1. 会社のWorkspaceの「顧客ID」を確認する。メールのドメインとは異なるIDです。
2. Directory APIのユーザー読み取り専用権限を持つ専用サービスアカウントを用意する。
3. ドメイン全体の委任で、スコープ `https://www.googleapis.com/auth/admin.directory.user.readonly` のみ許可する。
4. 委任先に、必要なユーザー情報を読める管理用アカウントを指定する。不要な書き込み権限を与えない。
5. サービスアカウント秘密鍵はCloudflare WorkersのSecretに直接登録する。ローカルやリポジトリに保存しない。
6. 管理者にする人が決まったら、その人のメールからDirectory APIで変更されないユーザーIDを確認する。`ADMIN_DIRECTORY_IDS`にはそのIDを登録する。メール表示名、入力したUSER ID、Googleの管理者フラグを自動的にYY-Talk管理者とは扱わない。

個人Gmailや他社Workspaceは、同じ形式のメールであっても、対象の顧客ID・有効状態を満たさなければ拒否します。停止・アーカイブ済みユーザーも拒否します。

## Cloudflareの担当者に依頼すること

1. 開発ホスト全体 `https://<開発ホスト>/*` を保護するSelf-hosted Accessアプリを作る。HTML、API、WebSocketを同じホストに置く。
2. Google Workspaceの会社用IdPだけを選択する。メールOTP・任意のGoogleログイン・Bypassルールをログインの代替にしない。
3. アクセスポリシーで `t-max.co.jp` の会社ユーザーを対象にし、IdPも会社用Googleに限定する。WorkerはさらにGoogle Directoryで在籍確認する。
4. AccessのアプリケーションAUDとチームURLを控える。AUDはGoogle OAuth Client IDとは別です。
5. `wrangler.toml` の開発Worker名は `yy-talk-security-dev`。本番ルート・本番名を指定するコマンドを使わない。開発ホストの接続・デプロイも実施前に承認を取る。
6. `workers_dev=false`、`preview_urls=false`、assetsの `run_worker_first=true` を維持する。ASSETSを単独公開しない。旧のassets.directory="."構成を引き継がない。
7. 次の設定を開発Workerに登録する。例のプレースホルダーを実値の代わりに使わない。

| 設定名 | 入れるもの |
|---|---|
| APP_ORIGIN | 開発用URLのorigin。末尾スラッシュなし。例: `https://intercom-dev.example.invalid` |
| ACCESS_ISSUER | `https://<会社のAccessチーム名>.cloudflareaccess.com` |
| ACCESS_AUD | 開発用AccessアプリのAUD |
| WORKSPACE_CUSTOMER_ID | Google Workspaceの実顧客ID |
| GOOGLE_SERVICE_ACCOUNT_EMAIL | Directory照会用サービスアカウント |
| GOOGLE_DELEGATED_ADMIN | 読み取り権限のある委任先アカウント |
| ADMIN_DIRECTORY_IDS | 管理者にするDirectory IDのJSON配列。未設定なら `[]` |
| ROOM_POLICY_JSON | 利用可能なROOMと参加方針。下の例を参照 |
| LIVEKIT_URL | 既存LiveKit Cloudの `wss://<project>.livekit.cloud` |

```json
{"YY-DEV":{"allowWorkspace":true,"defaultParties":["ch-video","ch1"]}}
```

これで会社の有効ユーザーは `YY-DEV` に一般社員として参加できます。`allowWorkspace:false` と `members:["<Directory ID>"]` でROOM自体を個別許可にもできます。パーティーは管理者がPATCH PANELで割り当てます。通常ユーザーにVIDEOを残してください。32パーティー、256登録ユーザーを上限として入力検証します。

次の値は通常の変数ではなくWorkerのSecretsに設定します。

- `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY`: Google担当者が用意する秘密鍵。
- `LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET`: 既存LiveKit Cloudのサーバー用鍵。ブラウザへは送りません。
- `ROOM_NAMESPACE_SECRET`: 開発用の十分に長いランダム値。本番と別にする。変更するとROOM名が変わるため、運用中の交換は切替作業として扱う。

キーの作成・交換、既存サービス停止、DNS変更、本番公開は本手順では自動実行しません。

## タリー送信機の接続変更

公開MQTTブローカーをブラウザから使う方法は廃止しました。既存のタリー送信機側にも変更が必要です。

1. `/api/bridge/tally` だけを対象に、専用のAccessアプリと専用サービス認証トークンを設定する。他のパスへのBypassを作らない。
2. Workerに `TALLY_AUD`（その専用アプリのAUD）、`TALLY_SERVICE_TOKEN_ID`（署名済みJWTのcommon_nameと照合する正確なサービスID）、`TALLY_ROOM`（対象の論理ROOM名）を設定する。
3. 送信機はCloudflare所定のサービス認証ヘッダーで同じ開発ホストへPOSTする。認証トークンのsecretは送信機の安全な設定領域へ保存し、ブラウザには配信しない。
4. Content-Typeを `application/json` とし、本文を以下の形式にする。

```json
{"type":"tally","id":1,"active":true}
```

OFFは `active:false`。この認証は指定ROOMのタリー変更だけを許し、アプリ閲覧、音声参加、PATCH PANEL操作は許しません。送信機のサービス認証を使った実送信は未検証です。旧機器の接続情報がないため、移行完了とはしていません。

## 変更を反映する前の確認

[検証表](TESTS-ja.md) を開発環境で埋めます。`workers.dev` やPages、プレビュー、古いトークンURLが認証を迂回しないことを別々に確認します。

本番への切替時は、公開済み固定管理者パスワードの廃止、旧Workerの制限、LiveKitキー交換、既存接続への影響、必要なDNS変更を一覧にして承認を取ります。承認後の作業も、未認証アクセスの実測で終了を確認してください。
