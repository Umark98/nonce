module shareobject::publickeys;

use sui::ed25519;
use sui::table::{Self, Table};

use shareobject::admin::AdminCap;

// Error Codes
const ESignatureNotVerified: u64 = 1;
const EEmptyKeyList: u64 = 4;
const EInvalidKeyFormat: u64 = 5;
const EKeyNotFound: u64 = 7;
const EKeyAlreadyExists: u64 = 9;


// Struct for storing public keys and nonces
public struct PublicKeys has key, store {
    id: UID,
    public_key_list: vector<vector<u8>>,
    nonce_table: Table<address, u64>,
}

// Create a shared signature list (AdminCap required)
public entry fun create_signature_list(
    _admin_cap: &AdminCap,
    public_key_list: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    assert!(!vector::is_empty(&public_key_list), EEmptyKeyList);

    let len = vector::length(&public_key_list);
    let mut i = 0;
    while (i < len) {
        assert!(vector::length(vector::borrow(&public_key_list, i)) == 32, EInvalidKeyFormat);
        let mut j = 0;
        while (j < i) {
            assert!(vector::borrow(&public_key_list, i) != vector::borrow(&public_key_list, j), EKeyAlreadyExists);
            j = j + 1;
        };
        i = i + 1;
    };

    let signature_wrapper = PublicKeys {
        id: object::new(ctx),
        public_key_list,
        nonce_table: table::new<address, u64>(ctx),
    };

    transfer::share_object(signature_wrapper);
}

// Add a public key (AdminCap required)
public entry fun add_publickey(
    _admin_cap: &AdminCap,
    signature_wrapper: &mut PublicKeys,
    new_publickey: vector<u8>,
    _ctx: &mut TxContext,
) {
    assert!(!vector::is_empty(&new_publickey), EEmptyKeyList);
    assert!(vector::length(&new_publickey) == 32, EInvalidKeyFormat);

    let len = vector::length(&signature_wrapper.public_key_list);
    let mut i = 0;
    while (i < len) {
        if (vector::borrow(&signature_wrapper.public_key_list, i) == &new_publickey) {
            abort EKeyAlreadyExists
        };
        i = i + 1;
    };

    vector::push_back(&mut signature_wrapper.public_key_list, new_publickey);
}

// Remove a public key (AdminCap required)
public entry fun remove_publickey(
    _admin_cap: &AdminCap,
    signature_wrapper: &mut PublicKeys,
    index: u64,
    _ctx: &mut TxContext,
) {
    assert!(vector::length(&signature_wrapper.public_key_list) > 1, EEmptyKeyList);
    assert!(index < vector::length(&signature_wrapper.public_key_list), EKeyNotFound);
    vector::remove(&mut signature_wrapper.public_key_list, index);
}

// Test function to verify signature
public entry fun test_function(
    signature_wrapper: &mut PublicKeys,
    signature: vector<u8>,
    msg: vector<u8>, // Message includes nonce + payload
    backend_id: u64,
    ctx: &TxContext,
) {
    let verified = verify_signature(signature_wrapper, &signature, backend_id, &msg, ctx);
    assert!(verified, ESignatureNotVerified);
}

// Verify signature with nonce check and message reconstruction
fun verify_signature(
    wrapper: &mut PublicKeys,
    signature: &vector<u8>,
    backend_id: u64,
    msg: &vector<u8>,
    ctx: &TxContext,
): bool {
    assert!(vector::length(signature) == 64, EInvalidKeyFormat);
    assert!(backend_id < vector::length(&wrapper.public_key_list), EKeyNotFound);

    let sender = tx_context::sender(ctx);

    // Check if the message has at least 8 bytes for the nonce
    if (vector::length(msg) < 8) {
        return false
    };

    // Extract the expected nonce from the message (first 8 bytes, little-endian)
    let expected_nonce = (
        (msg[0] as u64) |
        ((msg[1] as u64) << 8) |
        ((msg[2] as u64) << 16) |
        ((msg[3] as u64) << 24) |
        ((msg[4] as u64) << 32) |
        ((msg[5] as u64) << 40) |
        ((msg[6] as u64) << 48) |
        ((msg[7] as u64) << 56)
    );

    // Get the current nonce for the sender
    let current_nonce = get_nonce(wrapper, sender);

    // Check if the expected nonce matches the current nonce
    if (expected_nonce != current_nonce) {
        return false
    };

    // Extract the payload (everything after the first 8 bytes)
    let _payload_len = vector::length(msg) - 8;
    let mut payload = vector::empty<u8>();
    let mut i = 8;
    while (i < vector::length(msg)) {
        vector::push_back(&mut payload, *vector::borrow(msg, i));
        i = i + 1;
    };

    // Reconstruct the signed message: current_nonce + payload
    let mut signed_message = vector::empty<u8>();
    vector::append(&mut signed_message, u64_to_bytes(current_nonce));
    vector::append(&mut signed_message, payload);

    // Verify the signature on the reconstructed message
    let master_key = vector::borrow(&wrapper.public_key_list, backend_id);
    let verified = ed25519::ed25519_verify(signature, master_key, &signed_message);

    // If verified, increment the nonce
    if (verified) {
        if (table::contains(&wrapper.nonce_table, sender)) {
            let current_nonce = *table::borrow(&wrapper.nonce_table, sender);
            table::remove(&mut wrapper.nonce_table, sender);
            table::add(&mut wrapper.nonce_table, sender, current_nonce + 1);
        } else {
            table::add(&mut wrapper.nonce_table, sender, 1);
        };
    };

    verified
}

// Helper function to convert u64 to 8-byte vector (little-endian)
fun u64_to_bytes(value: u64): vector<u8> {
    let mut bytes = vector::empty<u8>();
    vector::push_back(&mut bytes, (value & 0xff as u8));
    vector::push_back(&mut bytes, ((value >> 8) & 0xff as u8));
    vector::push_back(&mut bytes, ((value >> 16) & 0xff as u8));
    vector::push_back(&mut bytes, ((value >> 24) & 0xff as u8));
    vector::push_back(&mut bytes, ((value >> 32) & 0xff as u8));
    vector::push_back(&mut bytes, ((value >> 40) & 0xff as u8));
    vector::push_back(&mut bytes, ((value >> 48) & 0xff as u8));
    vector::push_back(&mut bytes, ((value >> 56) & 0xff as u8));
    bytes
}

// Get the nonce of a specific user
public fun get_nonce(wrapper: &PublicKeys, user: address): u64 {
    if (table::contains(&wrapper.nonce_table, user)) {
        *table::borrow(&wrapper.nonce_table, user)
    } else {
        0
    }
}

// Get the list of public keys
public fun get_public_key_list(wrapper: &PublicKeys): vector<vector<u8>> {
    wrapper.public_key_list
}

// issue in the signer thats not verifying the signer correctly
// #[allow(duplicate_alias)]
// module shareobject::publickeys;

// use shareobject::admin::{AdminCap}; // Import AdminCap directly
// use sui::ed25519;
// use sui::table::{Self, Table};
// use sui::tx_context::{Self, TxContext};
// use sui::bcs;
// use sui::object::{Self, UID};
// use sui::transfer;

// // Error Codes
// const ESignatureNotVerified: u64 = 1;
// const EEmptyKeyList: u64 = 4;
// const EInvalidKeyFormat: u64 = 5;
// const EKeyNotFound: u64 = 7;
// // ENotAdmin removed as possession of AdminCap is sufficient

// public struct PublicKeys has key, store {
//     id: UID,
//     /// List of public keys (Ed25519, 32 bytes each) for trusted signers used in signature verification.
//     public_key_list: vector<vector<u8>>,
//     /// Table mapping user addresses to their current nonce for signature verification, preventing replay attacks.
//     nonce_table: Table<address, u64>,
//     /// The owner address, set to the admin who created this object and manages the public key list.
//     owner: address,
// }

// // Create a shared signature list (AdminCap required)
// // Only the admin possessing AdminCap can call this; no additional sender check needed.
// public entry fun create_signature_list(
//     _: &AdminCap, // Possession of AdminCap ensures admin-only access
//     public_key_list: vector<vector<u8>>,
//     ctx: &mut TxContext,
// ) {
//     assert!(!vector::is_empty(&public_key_list), EEmptyKeyList);

//     let len = vector::length(&public_key_list);
//     let mut i = 0;
//     while (i < len) {
//         assert!(vector::length(vector::borrow(&public_key_list, i)) == 32, EInvalidKeyFormat);
//         i = i + 1;
//     };

//     let signature_wrapper = PublicKeys {
//         id: object::new(ctx),
//         public_key_list,
//         nonce_table: table::new<address, u64>(ctx),
//         owner: tx_context::sender(ctx), // Admin's address recorded as owner
//     };

//     transfer::share_object(signature_wrapper);
// }


// public entry fun add_publickey(
//     _: &AdminCap, 
//     signature_wrapper: &mut PublicKeys,
//     new_publickey: vector<u8>,
//     _ctx: &mut TxContext, 
// ) {
//     assert!(!vector::is_empty(&new_publickey), EEmptyKeyList);
//     assert!(vector::length(&new_publickey) == 32, EInvalidKeyFormat);
//     vector::push_back(&mut signature_wrapper.public_key_list, new_publickey);
// }


// public entry fun remove_publickey(
//     _: &AdminCap, 
//     signature_wrapper: &mut PublicKeys,
//     index: u64,
//     _ctx: &mut TxContext, 
// ) {
//     assert!(vector::length(&signature_wrapper.public_key_list) > 1, EEmptyKeyList);
//     assert!(index < vector::length(&signature_wrapper.public_key_list), EKeyNotFound);
//     vector::remove(&mut signature_wrapper.public_key_list, index);
// }


// public fun construct_full_message(
//     wrapper: &PublicKeys,
//     msg: vector<u8>,
//     ctx: &TxContext,
// ): vector<u8> {
//     let sender = tx_context::sender(ctx);
    
//     let nonce = if (table::contains(&wrapper.nonce_table, sender)) {
//         *table::borrow(&wrapper.nonce_table, sender)
//     } else {
//         0
//     };
    
//     let sender_address_bytes = bcs::to_bytes(&sender);
//     let nonce_bytes = bcs::to_bytes(&nonce);

//     let mut full_message = vector::empty<u8>();
//     vector::append(&mut full_message, sender_address_bytes);
//     vector::append(&mut full_message, msg);
//     vector::append(&mut full_message, nonce_bytes);

//     full_message
// }

// // Test function for signature verification (public, no AdminCap needed)
// public entry fun test_function(
//     signature_wrapper: &mut PublicKeys,
//     signature: vector<u8>,
//     msg: vector<u8>,
//     backend_id: u64,
//     ctx: &TxContext,
// ) {
//     let verified = verify_signature(signature_wrapper, &signature, backend_id, &msg, ctx);
//     assert!(verified, ESignatureNotVerified);
// }

// // Verify a signature using a trusted public key (internal function)
// fun verify_signature(
//     wrapper: &mut PublicKeys,
//     signature: &vector<u8>,
//     backend_id: u64,
//     msg: &vector<u8>,
//     ctx: &TxContext,
// ): bool {
//     assert!(vector::length(signature) == 64, EInvalidKeyFormat);
//     assert!(backend_id < vector::length(&wrapper.public_key_list), EKeyNotFound);

//     let sender = tx_context::sender(ctx);
//     let master_key = vector::borrow(&wrapper.public_key_list, backend_id);

//     let nonce = if (table::contains(&wrapper.nonce_table, sender)) {
//         *table::borrow(&wrapper.nonce_table, sender)
//     } else {
//         0
//     };

//     let sender_address_bytes = bcs::to_bytes(&sender);
//     let nonce_bytes = bcs::to_bytes(&nonce);

//     let mut full_message = vector::empty<u8>();
//     vector::append(&mut full_message, sender_address_bytes);
//     vector::append(&mut full_message, *msg);
//     vector::append(&mut full_message, nonce_bytes);

//     let verified = ed25519::ed25519_verify(signature, master_key, &full_message);

//     if (verified) {
//         let new_nonce = nonce + 1;
//         if (table::contains(&wrapper.nonce_table, sender)) {
//             *table::borrow_mut(&mut wrapper.nonce_table, sender) = new_nonce;
//         } else {
//             table::add(&mut wrapper.nonce_table, sender, new_nonce);
//         };
//     };

//     verified
// }

// // Get the nonce of a specific user (public function, no AdminCap needed)
// public fun get_nonce(wrapper: &PublicKeys, user: address): u64 {
//     if (table::contains(&wrapper.nonce_table, user)) {
//         *table::borrow(&wrapper.nonce_table, user)
//     } else {
//         0
//     }
// }