// addPublicKey.js
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519'; // Added back the import
import { Transaction } from '@mysten/sui/transactions';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import * as ed from '@noble/ed25519';
import { createHash } from 'crypto';

// Constants
const NETWORK_URL = "https://fullnode.testnet.sui.io";
const PACKAGE_ID = '0x45c3c0f8b8b8d00903c8ae5db1d62440a467bf1b7f59a1d4adcd69bf3feb18c2';
const PROVIDED_MESSAGE = new Uint8Array([104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]);
const OBJECT_ID = "0x267b6e15166c59b9253b25f05b04c3423802a1eee7758357633d901850f50d69"; // Hardcoded objectId
const NEW_PUBLIC_KEY = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]); // Hardcoded public key

// SHA-512 configuration
ed.etc.sha512Sync = (...messages) => {
    const hash = createHash('sha512');
    messages.forEach((message) => hash.update(message));
    return hash.digest();
};
if (!ed.etc.sha512Sync) throw new Error('SHA-512 sync function not properly set');

// Keypair setup
const { secretKey } = decodeSuiPrivateKey(process.env.ADMIN_PRIVATE_KEY || 'suiprivkey1qzwv8tfh695z258dnm03nfp0x8d698t5gcayc85ym7kqxvaxvcmtv2trrqh');
const keypair = Ed25519Keypair.fromSecretKey(secretKey);

// Client setup
const client = new SuiClient({ url: NETWORK_URL });

function u64ToBytes(nonce) {
    const bytes = new Uint8Array(8);
    let temp = BigInt(nonce);
    for (let i = 7; i >= 0; i--) {
        bytes[i] = Number(temp & BigInt(0xFF));
        temp = temp >> BigInt(8);
    }
    return bytes;
}

async function executeTransaction(tx) {
    tx.setGasBudget(10000000);
    const result = await client.signAndExecuteTransaction({
        signer: keypair,
        transaction: tx,
        options: { showEffects: true },
        requestType: 'WaitForLocalExecution',
    });
    console.log('Transaction Result:', JSON.stringify(result.effects, null, 2));
    return result;
}

async function getObjectData(objectId) {
    const objectData = await client.getObject({ id: objectId, options: { showContent: true } });
    if (!objectData.data) throw new Error(`Object ${objectId} not found`);
    return objectData.data;
}

async function signMessage(message, secretKey, nonce) {
    const fullMsg = new Uint8Array([...message, ...u64ToBytes(nonce)]);
    return await ed.sign(fullMsg, secretKey); // Use raw secretKey directly
}

async function addPublicKey(objectId = OBJECT_ID, newPublicKey = NEW_PUBLIC_KEY) {
    if (!newPublicKey || newPublicKey.length !== 32) {
        throw new Error("Invalid public key: must be 32 bytes");
    }
    const objectData = await getObjectData(objectId);
    const currentNonce = BigInt(objectData.content.fields.nonce ?? '0');
    const addSignature = await signMessage(PROVIDED_MESSAGE, secretKey, currentNonce); // Use raw secretKey
    
    const tx = new Transaction();
    tx.moveCall({
        target: `${PACKAGE_ID}::publickeys::add_publickey`,
        arguments: [
            tx.object(objectId),
            tx.pure.vector("u8", Array.from(newPublicKey)),
            tx.pure.vector("u8", Array.from(addSignature)),
            tx.pure.vector("u8", Array.from(PROVIDED_MESSAGE)),
        ],
    });
    console.log('Adding new public key...');
    await executeTransaction(tx);
}

// Run if executed directly
if (process.argv[1].endsWith('addPublicKey.js')) {
    const objectId = process.argv[2] || OBJECT_ID;
    const keyArg = process.argv[3];
    const newPublicKey = keyArg ? new Uint8Array(keyArg.split(',').map(Number)) : NEW_PUBLIC_KEY;
    if (newPublicKey.length !== 32) {
        console.error('Public key must be exactly 32 bytes');
        process.exit(1);
    }
    addPublicKey(objectId, newPublicKey).catch((error) => console.error('Error:', error));
}