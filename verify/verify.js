// verify.js
// W3C Verifiable Credential 検証ロジック（正式版）

import { verifyES256K } from "https://cdn.jsdelivr.net/npm/@noble/secp256k1@2.1.0/+esm";

const btn = document.getElementById("verifyBtn");
const result = document.getElementById("result");

// Universal Resolver（グローバルDIDリゾルバAPI）
const UNIVERSAL_RESOLVER = "https://uniresolver.io/1.0/identifiers/";

btn.addEventListener("click", async () => {
  const jwt = document.getElementById("jwt").value.trim();
  if (!jwt) {
    alert("JWTを入力してください。");
    return;
  }

  try {
    // --- JWTの3分割（header.payload.signature） ---
    const [headerB64, payloadB64, signatureB64] = jwt.split(".");
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error("JWT形式が不正です（3つの部分に分割できません）。");
    }

    // --- Base64URLデコード ---
    const decode = (str) => {
      const pad = str.length % 4 === 0 ? str : str + "=".repeat(4 - (str.length % 4));
      const base64 = pad.replace(/-/g, "+").replace(/_/g, "/");
      return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    };
    const toJSON = (str) => JSON.parse(new TextDecoder().decode(decode(str)));

    const header = toJSON(headerB64);
    const payload = toJSON(payloadB64);
    const did = payload.iss;

    if (!did) throw new Error("DID (issuer) がJWT内に見つかりません。");

    // --- DID Document取得 ---
    const didResponse = await fetch(UNIVERSAL_RESOLVER + did);
    if (!didResponse.ok) throw new Error("DID Documentの取得に失敗しました。");
    const didDoc = await didResponse.json();
    const pubKeyJwk = didDoc.didDocument.verificationMethod[0].publicKeyJwk;

    if (!pubKeyJwk || !pubKeyJwk.x || !pubKeyJwk.y) {
      throw new Error("DID Document内に公開鍵情報が見つかりません。");
    }

    // --- 署名検証 ---
    const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = decode(signatureB64);

    const verified = await verifyES256K(signature, message, pubKeyJwk.x, pubKeyJwk.y);

    // --- 結果表示 ---
    result.textContent = JSON.stringify(
      {
        verified,
        issuer: payload.iss,
        subject: payload.sub,
        algorithm: header.alg,
        didDocumentId: didDoc.didDocument.id,
        verificationKey: didDoc.didDocument.verificationMethod[0].id,
        timestamp: new Date().toISOString(),
      },
      null,
      2
    );
  } catch (err) {
    console.error(err);
    result.textContent = `❌ エラー: ${err.message}`;
  }
});