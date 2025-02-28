module shareobject::gatekeeper_helper{
    use sui::ed25519;

    const ESignatureNotVerified: u64 = 1;

    
    public fun test_function<>(
        pubkey: vector<u8>,
        signature: vector<u8>,
        msg: vector<u8>,
        _ctx: &mut TxContext
    ) {
        let verified = ed25519::ed25519_verify(&signature, &pubkey, &msg);
        assert!(verified, ESignatureNotVerified);
    }

}
