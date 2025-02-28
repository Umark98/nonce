import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { fromHEX, toHEX } from '@mysten/sui/utils';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import * as ed from '@noble/ed25519';
import { createHash } from 'crypto';

// SHA-512 configuration
ed.etc.sha512Sync = (...messages) => {
    const hash = createHash('sha512');
    messages.forEach((message) => hash.update(message));
    return hash.digest();
};

if (!ed.etc.sha512Sync) throw new Error('SHA-512 sync function not properly set');

const client = new SuiClient({ url: "https://fullnode.testnet.sui.io" });
const PACKAGE_ID = '0x45c3c0f8b8b8d00903c8ae5db1d62440a467bf1b7f59a1d4adcd69bf3feb18c2';
const { secretKey } = decodeSuiPrivateKey('suiprivkey1qzwv8tfh695z258dnm03nfp0x8d698t5gcayc85ym7kqxvaxvcmtv2trrqh');
const keypair = Ed25519Keypair.fromSecretKey(secretKey);
const sender = keypair.getPublicKey().toSuiAddress();

const PROVIDED_MESSAGE = new Uint8Array([104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]);

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

// Function to get or create PublicKeys object
async function getOrCreatePublicKeysObject(existingObjectId = null) {
    let objectId = existingObjectId;
    
    if (!objectId) {
        console.log('No existing object ID provided, creating new PublicKeys object...');
        const tx = new Transaction();
        const adminPublicKey = keypair.getPublicKey().toRawBytes();
        tx.moveCall({
            target: `${PACKAGE_ID}::publickeys::create_signature_list`,
            arguments: [tx.pure.vector("vector<u8>", [Array.from(adminPublicKey)])],
        });
        const createResult = await executeTransaction(tx);
        objectId = createResult.effects?.created?.[0]?.reference?.objectId;
        if (!objectId) throw new Error("Failed to create PublicKeys object");
        console.log('Created PublicKeys Object ID:', objectId);
    } else {
        console.log('Using existing PublicKeys Object ID:', objectId);
        // Verify the object exists and is owned by sender
        const objectData = await client.getObject({ id: objectId, options: { showContent: true } });
        if (!objectData.data || objectData.data.content.fields.owner !== sender) {
            throw new Error("Invalid or inaccessible PublicKeys object");
        }
    }
    return objectId;
}

// Function to add a public key
async function addPublicKey(objectId, newPublicKey) {
    const objectData = await client.getObject({ id: objectId, options: { showContent: true } });
    const currentNonce = BigInt(objectData.data?.content?.fields.nonce ?? '0');
    const addMsg = new Uint8Array([...PROVIDED_MESSAGE, ...u64ToBytes(currentNonce)]);
    const addSignature = await ed.sign(addMsg, secretKey);
    
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

async function main() {
    console.log('Sender Address:', sender);

    // Specify an existing object ID here, or leave null to create a new one
    const EXISTING_OBJECT_ID ="0xaa4b94f1d17bc551c9b2e6a775bb85951061f64040c88f88f37cf3891c7930ab"; // Replace with object id if you want to add into the same object otherwise leave it null if you want to create a new object
    const objectId = await getOrCreatePublicKeysObject(EXISTING_OBJECT_ID);

    // Step 1: Get initial nonce
    const objectData = await client.getObject({ id: objectId, options: { showContent: true } });
    const initialNonce = BigInt(objectData.data?.content?.fields.nonce ?? '0');
    console.log('Initial Nonce:', initialNonce.toString());

    // Step 2: Sign message with admin key
    const msg = PROVIDED_MESSAGE;
    const nonceBytes = u64ToBytes(initialNonce);
    const fullMsg = new Uint8Array([...msg, ...nonceBytes]);
    console.log('Provided Message:', toHEX(msg));
    console.log('Nonce Bytes:', toHEX(nonceBytes));
    console.log('Full Message (msg + nonce):', toHEX(fullMsg));
    const signatureBytes = await ed.sign(fullMsg, secretKey);
    console.log('Generated Signature (admin key):', toHEX(signatureBytes));

    // Step 3: Call test_function
    const tx2 = new Transaction();
    tx2.moveCall({
        target: `${PACKAGE_ID}::publickeys::test_function`,
        arguments: [
            tx2.object(objectId),
            tx2.pure.vector("u8", Array.from(signatureBytes)),
            tx2.pure.vector("u8", Array.from(msg)),
            tx2.pure.u64(initialNonce.toString()),
        ],
    });
    console.log('Calling test_function with admin signature...');
    await executeTransaction(tx2);

    // Step 4: Verify updated nonce
    const updatedObjectData = await client.getObject({ id: objectId, options: { showContent: true } });
    const newNonce = BigInt(updatedObjectData.data?.content?.fields.nonce ?? '0');
    console.log('Updated Nonce:', newNonce.toString());

    // Step 5: Test replay protection
    const tx3 = new Transaction();
    tx3.moveCall({
        target: `${PACKAGE_ID}::publickeys::test_function`,
        arguments: [
            tx3.object(objectId),
            tx3.pure.vector("u8", Array.from(signatureBytes)),
            tx3.pure.vector("u8", Array.from(msg)),
            tx3.pure.u64(initialNonce.toString()),
        ],
    });
    console.log('Trying to reuse signature with old nonce...');
    try {
        await executeTransaction(tx3);
    } catch (error) {
        console.log('Expected Failure (EInvalidNonce):', error.message);
    }

    // Step 6: Add a new public key
    const newPublicKey1 = new Uint8Array(32).fill(1);
    await addPublicKey(objectId, newPublicKey1);

    // Step 7: Verify state after adding key
    const finalObjectData = await client.getObject({ id: objectId, options: { showContent: true } });
    console.log('State after adding key:', JSON.stringify(finalObjectData.data?.content, null, 2));
    const nonceAfterAdd = BigInt(finalObjectData.data?.content?.fields.nonce ?? '0');

    // Step 8: Add another public key (example)
    const newPublicKey2 = new Uint8Array(32).fill(2); // Another example key
    await addPublicKey(objectId, newPublicKey2);

    // Step 9: Verify state after adding second key
    const finalObjectData2 = await client.getObject({ id: objectId, options: { showContent: true } });
    console.log('State after adding second key:', JSON.stringify(finalObjectData2.data?.content, null, 2));

    // Optional Step 10: Remove a public key
    const shouldRemoveKey = false; // Set to false to skip key removal
    if (shouldRemoveKey) {
        const indexToRemove = 1;
        const removeMsg = new Uint8Array([...PROVIDED_MESSAGE, ...u64ToBytes(nonceAfterAdd)]);
        const removeSignature = await ed.sign(removeMsg, secretKey);
        const tx5 = new Transaction();
        tx5.moveCall({
            target: `${PACKAGE_ID}::publickeys::remove_publickey`,
            arguments: [
                tx5.object(objectId),
                tx5.pure.u64(indexToRemove),
                tx5.pure.vector("u8", Array.from(removeSignature)),
                tx5.pure.vector("u8", Array.from(PROVIDED_MESSAGE)),
            ],
        });
        console.log(`Removing public key at index ${indexToRemove}...`);
        await executeTransaction(tx5);

        const finalObjectDataAfterRemove = await client.getObject({ id: objectId, options: { showContent: true } });
        console.log('State after removing key:', JSON.stringify(finalObjectDataAfterRemove.data?.content, null, 2));
    } else {
        console.log('Skipping key removal...');
    }
}

main().catch((error) => {
    console.error('Error:', error);
});



//working but there is no removal of key
// import { SuiClient } from '@mysten/sui/client';
// import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
// import { Transaction } from '@mysten/sui/transactions';
// import { fromHEX, toHEX } from '@mysten/sui/utils';
// import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
// import * as ed from '@noble/ed25519';
// import { createHash } from 'crypto';

// // Ensure SHA-512 is configured correctly for noble/ed25519
// ed.etc.sha512Sync = (...messages) => {
//     const hash = createHash('sha512');
//     messages.forEach((message) => hash.update(message));
//     return hash.digest();
// };

// // Verify the configuration is applied
// if (!ed.etc.sha512Sync) {
//     throw new Error('SHA-512 sync function not properly set');
// }

// // Rest of your existing setup
// const client = new SuiClient({ url: "https://fullnode.testnet.sui.io" });
// const PACKAGE_ID = '0x80d3e0c488a8793136dff06fb51ba9a6e187cd6a815ea9befa3bbc58805ed055';
// const { secretKey } = decodeSuiPrivateKey('suiprivkey1qzwv8tfh695z258dnm03nfp0x8d698t5gcayc85ym7kqxvaxvcmtv2trrqh');
// const keypair = Ed25519Keypair.fromSecretKey(secretKey);
// const sender = keypair.getPublicKey().toSuiAddress();



// // Provided message
// const PROVIDED_MESSAGE = new Uint8Array([
//     104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100 // "hello world"
// ]);

// // Convert u64 nonce to 8-byte array (matches contract's u64_to_bytes)
// function u64ToBytes(nonce) {
//     const bytes = new Uint8Array(8);
//     let temp = BigInt(nonce);
//     for (let i = 7; i >= 0; i--) {
//         bytes[i] = Number(temp & BigInt(0xFF));
//         temp = temp >> BigInt(8);
//     }
//     return bytes;
// }

// // Execute a transaction
// async function executeTransaction(tx) {
//     tx.setGasBudget(10000000);
//     const result = await client.signAndExecuteTransaction({
//         signer: keypair,
//         transaction: tx,
//         options: { showEffects: true },
//         requestType: 'WaitForLocalExecution',
//     });
//     console.log('Transaction Result:', JSON.stringify(result.effects, null, 2));
//     return result;
// }

// async function main() {
//     console.log('Sender Address:', sender);

//     // Step 1: Create PublicKeys object with admin key (sole authority)
//     const tx1 = new Transaction();
//     const adminPublicKey = keypair.getPublicKey().toRawBytes(); // Admin key
//     tx1.moveCall({
//         target: `${PACKAGE_ID}::publickeys::create_signature_list`,
//         arguments: [
//             tx1.pure.vector("vector<u8>", [Array.from(adminPublicKey)]),
//         ],
//     });

//     console.log('Creating PublicKeys object with admin key...');
//     const createResult = await executeTransaction(tx1);
//     const objectId = createResult.effects?.created?.[0]?.reference?.objectId;
//     if (!objectId) throw new Error("Failed to create PublicKeys object");
//     console.log('PublicKeys Object ID:', objectId);

//     // Step 2: Get initial nonce
//     const objectData = await client.getObject({
//         id: objectId,
//         options: { showContent: true },
//     });
//     const initialNonce = BigInt(objectData.data?.content?.fields.nonce ?? '0');
//     console.log('Initial Nonce:', initialNonce.toString());

//     // Step 3: Sign provided message with nonce using admin key
//     const msg = PROVIDED_MESSAGE;
//     const nonceBytes = u64ToBytes(initialNonce);
//     const fullMsg = new Uint8Array([...msg, ...nonceBytes]);
//     console.log('Provided Message:', toHEX(msg));
//     console.log('Nonce Bytes:', toHEX(nonceBytes));
//     console.log('Full Message (msg + nonce):', toHEX(fullMsg));

//     const signatureBytes = await ed.sign(fullMsg, secretKey); // Raw signature with admin key
//     console.log('Generated Signature (admin key):', toHEX(signatureBytes));

//     // Step 4: Call test_function with admin signature
//     const tx2 = new Transaction();
//     tx2.moveCall({
//         target: `${PACKAGE_ID}::publickeys::test_function`,
//         arguments: [
//             tx2.object(objectId),
//             tx2.pure.vector("u8", Array.from(signatureBytes)),
//             tx2.pure.vector("u8", Array.from(msg)),
//             tx2.pure.u64(initialNonce.toString()),
//         ],
//     });

//     console.log('Calling test_function with admin signature...');
//     await executeTransaction(tx2);

//     // Step 5: Verify updated nonce
//     const updatedObjectData = await client.getObject({
//         id: objectId,
//         options: { showContent: true },
//     });
//     const newNonce = BigInt(updatedObjectData.data?.content?.fields.nonce ?? '0');
//     console.log('Updated Nonce:', newNonce.toString());

//     // Step 6: Test replay protection
//     const tx3 = new Transaction();
//     tx3.moveCall({
//         target: `${PACKAGE_ID}::publickeys::test_function`,
//         arguments: [
//             tx3.object(objectId),
//             tx3.pure.vector("u8", Array.from(signatureBytes)),
//             tx3.pure.vector("u8", Array.from(msg)),
//             tx3.pure.u64(initialNonce.toString()), // Old nonce, should fail
//         ],
//     });

//     console.log('Trying to reuse signature with old nonce...');
//     try {
//         await executeTransaction(tx3);
//     } catch (error) {
//         console.log('Expected Failure (EInvalidNonce):', error.message);
//     }

//     // Step 7: Add a new public key with admin approval
//     const newPublicKey = new Uint8Array(32).fill(1); // Example new key (32 bytes)
//     const addMsg = new Uint8Array([...PROVIDED_MESSAGE, ...u64ToBytes(newNonce)]); // Use updated nonce
//     const addSignature = await ed.sign(addMsg, secretKey);

//     const tx4 = new Transaction();
//     tx4.moveCall({
//         target: `${PACKAGE_ID}::publickeys::add_publickey`,
//         arguments: [
//             tx4.object(objectId),
//             tx4.pure.vector("u8", Array.from(newPublicKey)),
//             tx4.pure.vector("u8", Array.from(addSignature)),
//             tx4.pure.vector("u8", Array.from(PROVIDED_MESSAGE)),
//         ],
//     });

//     console.log('Adding new public key with admin signature...');
//     await executeTransaction(tx4);

//     // Step 8: Verify final state
//     const finalObjectData = await client.getObject({
//         id: objectId,
//         options: { showContent: true },
//     });
//     console.log('Final Object Data:', JSON.stringify(finalObjectData.data?.content, null, 2));
// }

// main().catch((error) => {
//     console.error('Error:', error);
// });