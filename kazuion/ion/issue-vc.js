// issue-vc.js — missing_issuer対応・完全安定版

import fs from 'fs'
import base64url from 'base64url'
import { ES256KSigner, createJWT } from 'did-jwt'

// ==========================
// 1️⃣ Founder VCを読み込み
// ==========================
const vc = JSON.parse(fs.readFileSync('./founder_vc.json', 'utf8'))

// ==========================
// 2️⃣ secretsフォルダから秘密鍵を読み込み
// ==========================
const jwk = JSON.parse(fs.readFileSync('./secrets/ion-privateJwk.json', 'utf8'))
const hexPriv = Buffer.from(base64url.toBuffer(jwk.d)).toString('hex')
const signer = ES256KSigner(Buffer.from(hexPriv, 'hex'))

// ==========================
// 3️⃣ 発行者 DIDを直接指定（明示）
// ==========================
const issuerDID = "did:ion:EiCLBKiG6J0qm6OU7lHSgoVf3wsbBBCCVvv57xND2a5RNg"

// ==========================
// 4️⃣ JWTペイロードを手動構築
// ==========================
const payload = {
  iss: issuerDID,
  sub: vc.credentialSubject.id,
  nbf: Math.floor(new Date(vc.issuanceDate).getTime() / 1000),
  vc
}

// ==========================
// 5️⃣ 署名付きJWTを生成
// ==========================
const jwt = await createJWT(payload, {
  issuer: issuerDID,
  signer,
  alg: 'ES256K'
})

// ==========================
// 6️⃣ 出力ファイル作成
// ==========================
fs.writeFileSync('./founder_vc.jwt', jwt)
console.log('✅ Founder ION VC 署名完了 → founder_vc.jwt')
console.log('--------------------------------------------')
console.log('✅ DID(issuer):', issuerDID)
console.log('✅ JWT VCを公開できます（WordPressやCloudflareなど）')