import { mnemonicToMiniSecret } from '@polkadot/util-crypto';
import * as secp from '@noble/secp256k1';
import * as jsonld from 'jsonld'; // For canonicalizing JSON-LD data
import { sha256 } from '@noble/hashes/sha256';
import base58 from 'bs58'
import { Secp256k1Key, Secp256k1Signature } from '@affinidi/tiny-lds-ecdsa-secp256k1-2019';
import * as jsigs from 'jsonld-signatures';

const mnemonic = 'test walk nut penalty hip pave soap entry language right filter choice';

const vcTemplate = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        {
          "credentialSchema": {
            "@id": "https://www.w3.org/2018/credentials#credentialSchema",
            "@type": "@id"
          },
          "email": {
            "@id": "schema-id:email",
            "@type": "https://schema.org/Text"
          },
          "name": {
            "@id": "schema-id:studentName",
            "@type": "https://schema.org/Text"
          },
          "courseName": {
            "@id": "schema-id:courseName",
            "@type": "https://schema.org/Text"
          },
          "instituteName": {
            "@id": "schema-id:instituteName",
            "@type": "https://schema.org/Text"
          },
          "instituteLogo": {
            "@id": "schema-id:instituteLogo",
            "@type": "https://schema.org/Text"
          },
          "dateOfCompletion": {
            "@id": "schema-id:dateOfCompletion",
            "@type": "https://schema.org/Text"
          },
          "scoreAchieved": {
            "@id": "schema-id:score",
            "@type": "https://schema.org/Text"
          }
        }
      ],
    "type": ["VerifiableCredential"]
};

async function signCredential(vc: any, key: any, verificationMethod: string) {
    /* suite is very important */
    const suite = new Secp256k1Signature({
        key,
	date: new Date().toISOString()
    });

    /* this is used for signing */
    const signedDoc = await jsigs.sign(
	{ ...vc },
	{
	    suite,
	    documentLoader: async (url) => {
		if (url.startsWith('https://')) {
		    /* does this always work? */
		    const response = await fetch(url);
		    const json = await response.json();
		    return {
			contextUrl: null,
			document: json,
			documentUrl: url
  		    };
		}
	    },
            purpose: new jsigs.purposes.AssertionProofPurpose(),
            compactProof: false,
	},
    )
    return signedDoc;
}

async function generateVC() {
    let vc = { ...vcTemplate };

    /* get the issuer-did and signing key */
    const seed = mnemonicToMiniSecret(mnemonic);
    const privateKey = seed.slice(0, 32);
    const publicKey = secp.getPublicKey(privateKey, true);

    /* this is key to get the proper did:key */
    const multicodecPrefixedKey = new Uint8Array([0xe7, 0x01, ...publicKey]);

    // Step 3: Base58btc encode the multicodec-prefixed key
    const encodedKey = base58.encode(multicodecPrefixedKey);
    
    const verificationMethod = `did:key:z${encodedKey}#z${encodedKey}`;
    const did = `did:key:z${encodedKey}`;
    
    const key = new Secp256k1Key({
	id: verificationMethod,
	controller: did,
        type: 'EcdsaSecp256k1VerificationKey2019',
	publicKeyHex: Buffer.from(publicKey).toString('hex'),
    	privateKeyHex: Buffer.from(privateKey).toString('hex')
    });

    vc.issuanceDate = new Date().toISOString();
    // Holder's unique id. Same as credentialSubjectid.
    vc.holder = {
	id: 'did:web:did.credissuer.com:4416cdba-f087-43a0-8513-dac140d2c997'
    };

    /* This should be the unique id generated per credential  */
    vc.id = "did:web:did.credissuer.com:b6d0e880-59ad-45b9-92f0-81e38e45012f";

    /* This needs to be based on the 'schema', and content for the schema */
    vc.credentialSubject = {
        "id": "did:web:did.credissuer.com:4416cdba-f087-43a0-8513-dac140d2c997",
        "email": "vijay.vujjini@gmail.com",
        "name": "Vijay Vujjini",
        "courseName": "Bachelors in Data Analytics (Dhiway)",
        "instituteName": "Unseen University",
        "instituteLogo": "",
        "dateOfCompletion": "28 Nov 2019",
        "scoreAchieved": "450/500"
      };

    /* this should be the 'did:key:' generated earlier, but with mnemonic, so it is always same for same issuer */
    vc.issuer = did;
    
    const signedVC = await signCredential(vc, key, verificationMethod);
    console.log("SignedVC: ", signedVC, '\n');
    console.log("For Affinidi: \n", JSON.stringify(signedVC, null, 2));
}

async function main() {
      await generateVC();
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally();

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    //Cord.disconnect();
    process.exit(0);
});
