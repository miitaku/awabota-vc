// verify.js — 正式W3C準拠版
document.addEventListener("DOMContentLoaded", () => {
  const verifyBtn = document.getElementById("verifyBtn");
  const result = document.getElementById("result");

  verifyBtn.addEventListener("click", async () => {
    const jwt = document.getElementById("jwtInput").value.trim();
    if (!jwt) {
      alert("JWTを入力してください。");
      return;
    }

    result.textContent = "検証中...";

    try {
      const parts = jwt.split(".");
      if (parts.length !== 3) throw new Error("JWTの形式が不正です。");
      const [headerB64, payloadB64, signatureB64] = parts;
      const header = JSON.parse(atob(headerB64));
      const payload = JSON.parse(atob(payloadB64));

      // 発行者DIDを抽出
      const did = payload.iss;
      if (!did) throw new Error("発行者DID (iss) が見つかりません。");

      // Universal ResolverでDID Documentを取得
      const resolverUrl = `https://uniresolver.io/1.0/identifiers/${did}`;
      const response = await fetch(resolverUrl);
      if (!response.ok) throw new Error("DID Documentを取得できませんでした。");
      const didDoc = await response.json();

      // DID DocumentからpublicKey取得
      const vm = didDoc.didDocument?.verificationMethod?.[0];
      if (!vm) throw new Error("verificationMethodが見つかりません。");
      const pubKeyJwk = vm.publicKeyJwk;
      if (!pubKeyJwk) throw new Error("publicKeyJwkが存在しません。");

      // ES256K署名検証（W3C準拠）
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "jwk",
        pubKeyJwk,
        { name: "ECDSA", namedCurve: "P-256K" },
        true,
        ["verify"]
      );

      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        key,
        Uint8Array.from(atob(signatureB64.replace(/_/g, "/").replace(/-/g, "+")), c => c.charCodeAt(0)),
        enc.encode(`${parts[0]}.${parts[1]}`)
      );

      result.textContent = JSON.stringify(
        {
          message: valid ? "✅ 署名検証成功" : "❌ 検証失敗",
          did,
          header,
          payload
        },
        null,
        2
      );
    } catch (e) {
      console.error(e);
      result.textContent = "⚠️ エラー: " + e.message;
    }
  });
});