const fs = require('fs');
const ion = require('@decentralized-identity/ion-tools');

(async () => {
  // 公開鍵JWKを読み込む
  const publicJwk = JSON.parse(fs.readFileSync('secrets/ion-publicJwk.json', 'utf-8'));

  // DIDを構築
  const did = new ion.DID({
    content: {
      publicKeys: [
        {
          id: 'key-1',
          type: 'EcdsaSecp256k1VerificationKey2019',
          publicKeyJwk: publicJwk,
          purposes: ['authentication']
        }
      ]
    }
  });

  // DID URIを取得（awaitが必要）
  const didUri = await did.getURI();
  console.log("あなたの ION DID:", didUri);
})();
