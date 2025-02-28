module shareobject::publickeys {
    use sui::ed25519;

    const ESignatureNotVerified: u64 = 1;
    const EInvalidOwner: u64 = 2;
    const EInvalidNonce: u64 = 3;
    const EEmptyKeyList: u64 = 4;
    const EInvalidKeyFormat: u64 = 5;
    const ETooManyKeys: u64 = 6;
    const EKeyNotFound: u64 = 7;
    const MAX_KEYS: u64 = 10;

    public struct PublicKeys has key, store {
        id: UID,
        public_key_list: vector<vector<u8>>,
        nonce: u64,
        owner: address,
    }

    public fun create_signature_list(
        public_key_list: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
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
            nonce: 0,
            owner: tx_context::sender(ctx),
        };
        transfer::share_object(signature_wrapper);
    }

    public fun add_publickey(
        signature_wrapper: &mut PublicKeys,
        new_publickey: vector<u8>,
        signature: vector<u8>,
        msg: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == signature_wrapper.owner, EInvalidOwner);
        assert!(!vector::is_empty(&new_publickey), EEmptyKeyList);
        assert!(vector::length(&signature_wrapper.public_key_list) < MAX_KEYS, ETooManyKeys);
        assert!(vector::length(&new_publickey) == 32, EInvalidKeyFormat);
        let verified = verify_signature(signature_wrapper, &signature, &msg);
        assert!(verified, ESignatureNotVerified);
        vector::push_back(&mut signature_wrapper.public_key_list, new_publickey);
        signature_wrapper.nonce = signature_wrapper.nonce + 1;
    }

    public fun remove_publickey(
        signature_wrapper: &mut PublicKeys,
        index: u64,
        signature: vector<u8>,
        msg: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == signature_wrapper.owner, EInvalidOwner);
        assert!(vector::length(&signature_wrapper.public_key_list) > 1, EEmptyKeyList); // Prevent removing last key
        let verified = verify_signature(signature_wrapper, &signature, &msg);
        assert!(verified, ESignatureNotVerified);
        assert!(index < vector::length(&signature_wrapper.public_key_list), EKeyNotFound);
        vector::remove(&mut signature_wrapper.public_key_list, index);
        signature_wrapper.nonce = signature_wrapper.nonce + 1;
    }

    public fun test_function(
        signature_wrapper: &mut PublicKeys,
        signature: vector<u8>,
        msg: vector<u8>,
        expected_nonce: u64,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == signature_wrapper.owner, EInvalidOwner);
        assert!(signature_wrapper.nonce == expected_nonce, EInvalidNonce);
        let verified = verify_signature(signature_wrapper, &signature, &msg);
        assert!(verified, ESignatureNotVerified);
        signature_wrapper.nonce = signature_wrapper.nonce + 1;
    }

    fun verify_signature(wrapper: &PublicKeys, signature: &vector<u8>, msg: &vector<u8>): bool {
        let master_key = vector::borrow(&wrapper.public_key_list, 0); // Admin key is at index 0
        let nonce_bytes = u64_to_bytes(wrapper.nonce);
        let mut new_msg = *msg;
        vector::append(&mut new_msg, nonce_bytes);
        ed25519::ed25519_verify(signature, master_key, &new_msg)
    }

    fun u64_to_bytes(num: u64): vector<u8> {
        let mut bytes = vector::empty<u8>();
        vector::push_back(&mut bytes, (num >> 56) as u8);
        vector::push_back(&mut bytes, (num >> 48) as u8);
        vector::push_back(&mut bytes, (num >> 40) as u8);
        vector::push_back(&mut bytes, (num >> 32) as u8);
        vector::push_back(&mut bytes, (num >> 24) as u8);
        vector::push_back(&mut bytes, (num >> 16) as u8);
        vector::push_back(&mut bytes, (num >> 8) as u8);
        vector::push_back(&mut bytes, num as u8);
        bytes
    }

    public fun get_nonce(wrapper: &PublicKeys): u64 {
        wrapper.nonce
    }
}




// module shareobject::publickeys {
//     use sui::ed25519;
    
//     const ESignatureNotVerified: u64 = 1;
//     const EInvalidOwner: u64 = 2;
//     const EInvalidNonce: u64 = 3;
//     const EEmptyKeyList: u64 = 4;
//     const EInvalidKeyFormat: u64 = 5;
//     const ETooManyKeys: u64 = 6;
//     const MAX_KEYS: u64 = 10;
// public struct PublicKeys has key, store {
//     id: UID,
//     public_key_list: vector<vector<u8>>,
//     nonce: u64,
//     owner: address,
// }

// public fun create_signature_list(
//     public_key_list: vector<vector<u8>>,
//     ctx: &mut TxContext
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
//         nonce: 0,
//         owner: tx_context::sender(ctx),
//     };
//     transfer::share_object(signature_wrapper);
// }

// public fun add_publickey(
//     signature_wrapper: &mut PublicKeys,
//     new_publickey: vector<u8>,
//     signature: vector<u8>,
//     msg: vector<u8>,
//     ctx: &mut TxContext
// ) {
//     assert!(tx_context::sender(ctx) == signature_wrapper.owner, EInvalidOwner);
//     assert!(!vector::is_empty(&new_publickey), EEmptyKeyList);
//     assert!(vector::length(&signature_wrapper.public_key_list) < MAX_KEYS, ETooManyKeys);
//     assert!(vector::length(&new_publickey) == 32, EInvalidKeyFormat);
//     let verified = verify_signature(signature_wrapper, &signature, &msg);
//     assert!(verified, ESignatureNotVerified);
//     vector::push_back(&mut signature_wrapper.public_key_list, new_publickey);
//     signature_wrapper.nonce = signature_wrapper.nonce + 1;
// }


// public fun test_function(
//     signature_wrapper: &mut PublicKeys,
//     signature: vector<u8>,
//     msg: vector<u8>,
//     expected_nonce: u64,
//     ctx: &mut TxContext
// ) {
//     assert!(tx_context::sender(ctx) == signature_wrapper.owner, EInvalidOwner);
//     assert!(signature_wrapper.nonce == expected_nonce, EInvalidNonce);
//     let verified = verify_signature(signature_wrapper, &signature, &msg);
//     assert!(verified, ESignatureNotVerified);
//     signature_wrapper.nonce = signature_wrapper.nonce + 1;
// }

// fun verify_signature(wrapper: &PublicKeys, signature: &vector<u8>, msg: &vector<u8>): bool {
//     let master_key = vector::borrow(&wrapper.public_key_list, 0);
//     let nonce_bytes = u64_to_bytes(wrapper.nonce);
//     let mut new_msg = *msg; // Dereference to get owned value
//     vector::append(&mut new_msg, nonce_bytes);
//     ed25519::ed25519_verify(signature, master_key, &new_msg)
// }

// fun u64_to_bytes(num: u64): vector<u8> {
//     let mut bytes = vector::empty<u8>();
//     vector::push_back(&mut bytes, (num >> 56) as u8);
//     vector::push_back(&mut bytes, (num >> 48) as u8);
//     vector::push_back(&mut bytes, (num >> 40) as u8);
//     vector::push_back(&mut bytes, (num >> 32) as u8);
//     vector::push_back(&mut bytes, (num >> 24) as u8);
//     vector::push_back(&mut bytes, (num >> 16) as u8);
//     vector::push_back(&mut bytes, (num >> 8) as u8);
//     vector::push_back(&mut bytes, num as u8);
//     bytes
// }

// public fun get_nonce(wrapper: &PublicKeys): u64 {
//     wrapper.nonce
// }
// }