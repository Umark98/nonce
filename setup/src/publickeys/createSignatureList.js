// createSignatureList.js
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import * as ed from '@noble/ed25519';
import { createHash } from 'crypto';

// Constants
const NETWORK_URL = "https://fullnode.testnet.sui.io";
const PACKAGE_ID = '0x45c3c0f8b8b8d00903c8ae5db1d62440a467bf1b7f59a1d4adcd69bf3feb18c2';

// SHA-512 configuration
ed.etc.sha512Sync = (...messages) => {
    const hash = createHash('sha512');
    messages.forEach((message) => hash.update(message));
    return hash.digest();
};
if (!ed.etc.sha512Sync) throw new Error('SHA-512 sync function not properly set');

// Keypair setup
const keypair = Ed25519Keypair.fromSecretKey(
    decodeSuiPrivateKey(process.env.ADMIN_PRIVATE_KEY || 'suiprivkey1qzwv8tfh695z258dnm03nfp0x8d698t5gcayc85ym7kqxvaxvcmtv2trrqh').secretKey
);

// Client setup
const client = new SuiClient({ url: NETWORK_URL });

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

async function createSignatureList() {
    console.log('Creating new PublicKeys object...');
    const tx = new Transaction();
    const adminPublicKey = keypair.getPublicKey().toRawBytes();
    tx.moveCall({
        target: `${PACKAGE_ID}::publickeys::create_signature_list`,
        arguments: [tx.pure.vector("vector<u8>", [Array.from(adminPublicKey)])],
    });
    const createResult = await executeTransaction(tx);
    const objectId = createResult.effects?.created?.[0]?.reference?.objectId;
    if (!objectId) throw new Error("Failed to create PublicKeys object");
    console.log('Created PublicKeys Object ID:', objectId);
    return objectId;
}

// Run if executed directly
if (process.argv[1].endsWith('createSignatureList.js')) {
    createSignatureList().catch((error) => console.error('Error:', error));
}