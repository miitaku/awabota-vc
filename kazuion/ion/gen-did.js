const ion = require('@decentralized-identity/ion-tools');
const fs  = require('fs');
const path = require('path');

(async () => {
  // 1) 鍵ペア生成
  const keyPair = await ion.generateKeyPair(); // { publicJwk, privateJwk }

  // 2) DID作成（ローカル）
  const did = new ion.DID({
    content: {
      publicKeys: [
        {
          id: 'key-1',
          type: 'EcdsaSecp256k1VerificationKey2019',
          publicKeyJwk: keyPair.publicJwk,
          purposes: ['authentication']
        }
      ]
    }
  });

  // 3) DIDのURIを表示
  const didUri = await did.getURI();
  console.log('あなたの ION DID:', didUri);

  // 4) 保存用ディレクトリ（700）を作成
  const dir = path.join(process.cwd(), 'secrets');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  // 5) ファイルへ安全に保存（mode: 600）
  const writeJSON = (p, obj) =>
    fs.writeFileSync(p, JSON.stringify(obj, null, 2), { mode: 0o600 });

  writeJSON(path.join(dir, 'ion-privateJwk.json'), keyPair.privateJwk); // 秘密鍵⚠️
  writeJSON(path.join(dir, 'ion-publicJwk.json'),  keyPair.publicJwk);  // 公開鍵

  // 6) 将来Publishするための Create リクエストも保存
  const request = await did.generateRequest();
  writeJSON(path.join(dir, 'ion-create-request.json'), request);

  console.log('保存しました → secrets/ion-privateJwk.json, ion-publicJwk.json, ion-create-request.json');
  console.log('※ secrets フォルダは個人専用ストレージに保管し、共有しないでください。');
})();
