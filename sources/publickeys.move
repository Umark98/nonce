module shareobject::publickeys;

use shareobject::admin::{Self, AdminCap};
use sui::ed25519;
use sui::table::{Self, Table};

// Error Codes
const ESignatureNotVerified: u64 = 1;
const EEmptyKeyList: u64 = 4;
const EInvalidKeyFormat: u64 = 5;
const EKeyNotFound: u64 = 7;
const ENotAdmin: u64 = 8;

// Struct for storing public keys and nonces
public struct PublicKeys has key, store {
    id: UID,
    public_key_list: vector<vector<u8>>,
    nonce_table: Table<address, u64>,
    owner: address,
}

// Create a shared signature list (AdminCap required)
public entry fun create_signature_list(
    admin_cap: &AdminCap,
    public_key_list: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    assert!(sender == admin::admin_owner(admin_cap), ENotAdmin);
    assert!(!vector::is_empty(&public_key_list), EEmptyKeyList);

    let len = vector::length(&public_key_list);
    let mut i = 0;
    while (i < len) {
        assert!(vector::length(vector::borrow(&public_key_list, i)) == 32, EInvalidKeyFormat);
        i = i + 1;
    };

    let signature_wrapper = PublicKeys {
        id: object::new(ctx),
        public_key_list,
        nonce_table: table::new<address, u64>(ctx),
        owner: sender,
    };

    transfer::share_object(signature_wrapper);
}

// Add a public key (AdminCap required)
public entry fun add_publickey(
    admin_cap: &AdminCap,
    signature_wrapper: &mut PublicKeys,
    new_publickey: vector<u8>,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    assert!(sender == admin::admin_owner(admin_cap), ENotAdmin);
    assert!(!vector::is_empty(&new_publickey), EEmptyKeyList);
    assert!(vector::length(&new_publickey) == 32, EInvalidKeyFormat);
    vector::push_back(&mut signature_wrapper.public_key_list, new_publickey);
}

// Remove a public key (AdminCap required)
public entry fun remove_publickey(
    admin_cap: &AdminCap,
    signature_wrapper: &mut PublicKeys,
    index: u64,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    assert!(sender == admin::admin_owner(admin_cap), ENotAdmin);
    assert!(vector::length(&signature_wrapper.public_key_list) > 1, EEmptyKeyList);
    assert!(index < vector::length(&signature_wrapper.public_key_list), EKeyNotFound);
    vector::remove(&mut signature_wrapper.public_key_list, index);
}

public entry fun test_function(
    signature_wrapper: &mut PublicKeys,
    signature: vector<u8>,
    msg: vector<u8>,
    backend_id: u64,
    ctx: &TxContext,
) {
    let verified = verify_signature(signature_wrapper, &signature, backend_id, &msg, ctx);
    assert!(verified, ESignatureNotVerified);
}

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
    let master_key = vector::borrow(&wrapper.public_key_list, backend_id);

    // Verify the signature
    let verified = ed25519::ed25519_verify(signature, master_key, msg);

    // If verified, increment nonce
    if (verified) {
        // Increment Nonce
        if (table::contains(&wrapper.nonce_table, sender)) {
            let current_nonce = *table::borrow(&wrapper.nonce_table, sender);
            table::add(&mut wrapper.nonce_table, sender, current_nonce + 1);
        } else {
            table::add(&mut wrapper.nonce_table, sender, 1);
        }
    };

    verified
}

// Get the nonce of a specific user
public fun get_nonce(wrapper: &PublicKeys, user: address): u64 {
    if (table::contains(&wrapper.nonce_table, user)) {
        *table::borrow(&wrapper.nonce_table, user)
    } else {
        0
    }
}
