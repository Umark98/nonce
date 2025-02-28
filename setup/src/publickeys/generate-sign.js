import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519'
import { fromB64, toB64 } from '@mysten/bcs';


(async () => {
   
    const signerKeypair = new Ed25519Keypair();

   
    const secretKey = signerKeypair.getSecretKey() 

    const keypair = Ed25519Keypair.fromSecretKey(secretKey)
    const publicKey = keypair.getPublicKey()
    const message = new TextEncoder().encode('hello world');
    const signature = await keypair.sign(message);
    console.log("=======================================");
    console.log("Signature (Base64):");
    
    console.dir(Array.from(signature), { maxArrayLength: null });
    
    console.log("=======================================");
    
    
    console.log('Message (Base64):', message); 
    
    const privKeyArray = Uint8Array.from(Array.from(fromB64(secretKey)));
    const recoveredKeypair = await Ed25519Keypair.fromSecretKey(secretKey);

    // console.log('Private Key (Base64):', secretKey, 'test', privKeyArray);
    // console.log('Sample Message:', 'Hello, Sui Blockchain!');
    console.log('Public Key:', signerKeypair.getPublicKey());
    console.log('Recovered Public Key:', recoveredKeypair.getPublicKey());
})();