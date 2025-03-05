module shareobject::admin {
    /// Struct representing administrative privileges
    public struct AdminCap has key, store {
        id: UID,
        owner: address,
    }

    /// Creates an AdminCap object
    public fun create_admin_cap(ctx: &mut TxContext): AdminCap {
        let sender = tx_context::sender(ctx);
        AdminCap {
            id: object::new(ctx),
            owner: sender,
        }
    }

    /// Getter function to retrieve the owner of the AdminCap
    public fun admin_owner(admin_cap: &AdminCap): address {
        admin_cap.owner
    }
}
