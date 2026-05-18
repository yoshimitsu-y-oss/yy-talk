export default {
  async fetch(request, env, ctx) {
    // 1. CORS対応 (YY-Talkの画面からアクセスできるようにする許可証)
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // 2. URLから「ルーム名」と「ユーザー名」を受け取る
    const url = new URL(request.url);
    const room = url.searchParams.get("room");
    const user = url.searchParams.get("user");

    if (!room || !user) {
      return new Response("エラー: ルーム名とユーザー名が必要です", { status: 400, headers: corsHeaders });
    }

    // 3. Cloudflareの金庫からLiveKitの鍵を取り出す
    const apiKey = env.LIVEKIT_API_KEY;
    const apiSecret = env.LIVEKIT_API_SECRET;

    if (!apiKey || !apiSecret) {
      return new Response("エラー: サーバーの鍵が設定されていません", { status: 500, headers: corsHeaders });
    }

    // 4. Base64Url エンコード用のヘルパー関数
    const base64UrlEncode = (source) => {
      let encoded = btoa(String.fromCharCode.apply(null, new Uint8Array(source)));
      return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };

    // 5. パスポート（JWTトークン）の中身を作成
    const header = { alg: "HS256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: apiKey,
      sub: user,
      nbf: now,
      exp: now + 7200, // パスポートの有効期限（2時間）
      video: {
        roomJoin: true,
        room: room
      }
    };

    const encoder = new TextEncoder();
    const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
    const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
    const tokenData = `${encodedHeader}.${encodedPayload}`;

    // 6. Web Crypto API を使って偽造防止の署名（ハンコ）を押す
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(apiSecret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(tokenData));
    const encodedSignature = base64UrlEncode(signature);

    // 7. 完成したパスポートを合体させて返す
    const token = `${tokenData}.${encodedSignature}`;

    return new Response(JSON.stringify({ token: token }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
};
