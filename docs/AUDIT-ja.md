# 監査結果・変更計画

監査日: 2026-11-06（日本時間）。対象 main: `c8367502619ef24ace8e2c06cbd485c665ef684f`。
Cloudflareアカウントの管理情報・本番認証情報は環境に接続されていない。実環境のAccess、Pages、Workers、DNS設定は未確認。GitHub接続は読み書き可能。

## 基準版の比較

main のHTML先頭は `v55 headset PTT test, based on v51`。main履歴の確認対象HTMLにもv56表記なし。提供された `YY-Talk_Broadcast_Intercom_v56_Headset_PTT_Media_Display_Fix.html` を基準とした。

提供ファイルのSHA-256: `591fa72ef535ae44ff3faea2d344347a8a54c92dd1fb4bc3528da40085c0f6d2`。

v55→v56の主な変更はPTT有効時だけ無音メディアを再生すること、解除時のpause・再生位置初期化・MediaSession情報クリア、状態表示追加。これらを維持する。
提供ファイルにも固定管理者パスワードが含まれたため、その認証行を除去してから最初の取り込みコミットを作成する。秘密情報を新しいコミットに再掲載しない。

## 発見事項

| 重大度 | 証拠（監査時main） | 内容・対応 |
|---|---|---|
| Critical | `worker.js` | 認証なしで任意のroom/userにトークンを発行。ローカルでダミー鍵を使い再現。Access署名検証・Workspace在籍照会・ROOMポリシーへ置換 |
| Critical | `index.html:7081` | 固定管理者パスワードと特定ユーザー名による検証迂回。ブラウザから削除し、Google Directoryの不変IDによるサーバー判定へ置換 |
| High | `index.html:6776`, `7468` | LiveKit Dataの管理操作を送信者権限検証なしで適用。Data送信権限をトークンで禁止し、受信処理を廃止。管理操作はWorker→Durable Objectで検証 |
| High | `index.html:7104`, `7264` | 公開MQTTブローカーへ匿名接続。タリー偽装・presence偽装が可能。ブラウザMQTTを廃止し、限定されたAccessサービス認証のタリーAPIへ変更 |
| High | `index.html:5956` | パーティー音声は単一ROOM内のクライアントGainで分配。UI非表示やLISTEN OFFは情報アクセス制御にならない。パーティーごとにSFU ROOMを分離 |
| High | `cloudflare/workers-autoconfig/wrangler.jsonc` | assets.directoryがリポジトリ全体を指す。静的公開経路がアプリ認証を迂回する可能性。配信対象をpublicだけにし、全アセット要求をWorkerで先に認証 |
| Medium | `worker.js` | ワイルドカードCORS、GETによる発行、ユーザー指定identity、2時間の有効期間。same-origin POST・サーバーidentity・60秒トークンへ変更 |

## 実装を分ける単位

1. 提供v56の取り込み（固定パスワード除去済み）。本番mainは変更しない。
2. AccessのRS256署名・issuer・audience・期限検証、Google DirectoryのcustomerId・suspended・archived検証、Workerでの配信ゲート、管理者ID指定、ROOM制御。
3. v56 UIへの接続、公開MQTTとLiveKit Dataによる設定同期を廃止、認証付きHTTP変更とWebSocket同期、パーティー別音声ROOM、4W/PGMの送信前左右分離。
4. 自動テスト、監査資料、会社用セットアップ手順、実環境・実機の未検証項目を記録。

## 権限と音声

- ブラウザの管理者表示は利便性のため。管理操作の可否は毎回Workerが認証したactorで判定。リクエスト中のadmin/user/sender/roomを権限の根拠にしない。
- `ROOM_POLICY_JSON`に登録されたROOMだけ利用可能。会社の有効なWorkspaceユーザーを許可するROOM、IDの個別許可ROOMを設定できる。
- 管理者は登録されたGoogle Directory IDに限定。初期設定の管理者リストは空。
- 通常ユーザーはサーバー割当のパーティーだけトークンを取得可能。Listenパーティーは通常ユーザー送信不可。管理者はROOM内全パーティーを操作できる。
- 音声ROOMはパーティーごと、映像ROOMは別。一般ユーザーは映像送信不可。映像ROOMには音声ソースを公開できない。
- 4W/PGMのL/RをブラウザのWeb Audioで分離して別々に公開。片側だけの権限で反対側の音声を受信できない構成。
- ACL・パーティー種別・I/O割当変更時は旧SFU ROOMを削除し、generationを変える。削除APIが失敗した場合は新しいACLを確定しない。変更に伴う音声・映像の一時切断がある。
- トークンの期限は発行から60秒、nbfは時計ずれ用に5秒前。期限だけでは既存接続が切れないため、認証済みHTTPの最終確認から90秒でlease失効、30秒間隔のDO alarmで参加者を削除する。
- Workspace照会の肯定結果は15秒だけキャッシュする。失効検出・切断には通常最大約135秒かかる。外部API障害時は延長を認めず、削除はLiveKitの可用性に依存する。即時失効を保証する実装ではない。
- WebSocket入力で権限変更やlease延長はできない。変更とlease延長は認証済みHTTPのみ。ソケットは25秒で再認証し、HTTPで5秒ごとに状態照会する。
- VIDEO権限を外したユーザーは現状ROOM接続を完了できない。音声だけの接続を必要とする場合は別途クライアント対応が必要。既定のVIDEO割当を維持すること。

## 公開履歴の秘密情報

mainの242コミットのメタデータを確認し、237の参照時点の `index.html` と、`worker.js` の変更5時点をパターン検査。固定管理者パスワードの埋め込みをHTML参照202件で検出。別ブランチ `cloudflare/workers-autoconfig` の現行HTMLにも固定パスワードを検出した。値はこの資料・PR・新しいコミットへ転載しない。

この検査では `apiSecret` / `LIVEKIT_API_SECRET` / `api_secret` の文字列リテラル割当、PEM形式の秘密鍵は検出しなかった。全ファイル・削除済みref・fork・外部公開物の網羅的な秘密情報検査ではなく、漏洩がないことを保証しない。

| 対象 | 対応 |
|---|---|
| 公開済み固定管理者パスワード | 廃止。他サービスで使い回している場合は、そのサービスでも交換が必要 |
| LiveKit APIキー／秘密鍵 | 文字列漏洩は未確認。ただし未認証の発行口があったため、既発行トークンの不正利用を想定し、切替時のキー交換を推奨。承認なしでは実行しない |
| Cloudflare APIトークン／Googleサービスアカウント鍵 | 今回の対象から漏洩を確認していない。導入時は新しい用途限定設定を用意し、既存鍵の流用有無を管理者が確認する |
| 公開MQTT | 匿名ブローカーなので交換する認証情報がない。新経路で認証を必須にする |

公開GitHubの旧HTMLや履歴は、Cloudflare Accessでは隠せない。GitHub Pages、別ブランチ、raw URL、コピー、キャッシュ、forkの残存を別に扱う必要がある。公開リポジトリ自体の非公開化や履歴削除はこの作業では実行しない。

## 本番切替前の承認事項

このPRだけで現行公開経路の保護は完了しない。本番導入の前に、承認を受けて以下を実施・検証する。

1. Google Workspace専用IdPを選んだAccessアプリを開発用の全パスに設定し、開発Workerに必要な値とSecretsを登録する。
2. 実ログイン4パターンとLiveKit・機材の回帰テストを完了する。
3. 旧のトークンWorker、Pages、workers.dev、プレビュー、別ホスト、別ブランチ配信、カスタムドメインを棚卸しし、保護または停止する。既存サービスの停止は個別承認が必要。
4. LiveKitキー交換と既存接続の扱いを承認・実施する。停止時間を合意する。
5. DNS／本番ルートの変更と本番デプロイを承認・実施し、全公開経路で未認証アクセスを再検査する。

本作業中に本番公開、既存サービス停止、鍵交換、DNS変更は行わない。
