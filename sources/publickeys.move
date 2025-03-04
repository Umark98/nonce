#[allow(unused_variable, duplicate_alias)]
module shareobject::publickeys {
    use sui::ed25519;
    use sui::table::{Self, Table};
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    const ESignatureNotVerified: u64 = 1;
    const EEmptyKeyList: u64 = 4;
    const EInvalidKeyFormat: u64 = 5;
    const EKeyNotFound: u64 = 7;
    const ENotAdmin: u64 = 8;
    

    public struct AdminCap has key, store {
        id: UID,
        owner: address
    }

    public struct PublicKeys has key, store {
        id: UID,
        public_key_list: vector<vector<u8>>,
        nonce_table: Table<address, u64>, // Per-user nonce table
        owner: address,
    }

    // Create the AdminCap (called once by the initial admin)
    public entry fun create_admin_cap(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let admin_cap = AdminCap {
            id: object::new(ctx),
            owner: sender
        };
        transfer::transfer(admin_cap, sender);
    }

    // Create a shared signature list requiring AdminCap
    public entry fun create_signature_list(
        admin_cap: &AdminCap,
        public_key_list: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        assert!(sender == admin_cap.owner, ENotAdmin);
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
            nonce_table: table::new<address, u64>(ctx), // Starts empty
            owner: sender,
        };
        
        transfer::share_object(signature_wrapper);
    }

    // Add a public key (AdminCap restricted)
    public entry fun add_publickey(
        admin_cap: &AdminCap,
        signature_wrapper: &mut PublicKeys,
        new_publickey: vector<u8>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        assert!(sender == admin_cap.owner, ENotAdmin);
        assert!(!vector::is_empty(&new_publickey), EEmptyKeyList);
        assert!(vector::length(&new_publickey) == 32, EInvalidKeyFormat);
        vector::push_back(&mut signature_wrapper.public_key_list, new_publickey);
    }

    // Remove a public key (AdminCap restricted)
    public entry fun remove_publickey(
        admin_cap: &AdminCap,
        signature_wrapper: &mut PublicKeys,
        index: u64,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        assert!(sender == admin_cap.owner, ENotAdmin);
        assert!(vector::length(&signature_wrapper.public_key_list) > 1, EEmptyKeyList);
        assert!(index < vector::length(&signature_wrapper.public_key_list), EKeyNotFound);
        vector::remove(&mut signature_wrapper.public_key_list, index);
    }

    // Test signature verification
    public entry fun test_function(
        signature_wrapper: &mut PublicKeys,
        signature: vector<u8>,
        backend_id: u64,
        ctx: &TxContext
    ) {
        let verified = verify_signature(signature_wrapper, &signature, backend_id, ctx);
        assert!(verified, ESignatureNotVerified);
    }

    // Verify signature with per-user nonce table
    fun verify_signature(
        wrapper: &mut PublicKeys,
        signature: &vector<u8>,
        backend_id: u64,
        ctx: &TxContext
    ): bool {
        assert!(backend_id < vector::length(&wrapper.public_key_list), EKeyNotFound);
        let sender = tx_context::sender(ctx); // User address is the sender
        let master_key = vector::borrow(&wrapper.public_key_list, backend_id);
        
        // Get or initialize the nonce for the sender
        let nonce = if (table::contains(&wrapper.nonce_table, sender)) {
            *table::borrow(&wrapper.nonce_table, sender)
        } else {
            table::add(&mut wrapper.nonce_table, sender, 0);
            0
        };
        
        // Construct the message from digest and nonce
        let nonce_bytes = u64_to_bytes(nonce);
        let digest = *tx_context::digest(ctx);
        let mut msg = vector::empty<u8>();
        vector::append(&mut msg, digest);
        vector::append(&mut msg, nonce_bytes);

        // Verify the signature
        let verified = ed25519::ed25519_verify(signature, master_key, &msg);
        
        // Increment the nonce if verified
        if (verified) {
            if (table::contains(&wrapper.nonce_table, sender)) {
                table::remove(&mut wrapper.nonce_table, sender);
            };
            table::add(&mut wrapper.nonce_table, sender, nonce + 1);
        };
        
        verified
    }

    // Convert u64 to bytes for nonce
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

    // Get nonce for a specific user
    public fun get_nonce(wrapper: &PublicKeys, user: address): u64 {
        if (table::contains(&wrapper.nonce_table, user)) {
            *table::borrow(&wrapper.nonce_table, user)
        } else {
            0 // Return 0 for non-existent users
        }
    }
}