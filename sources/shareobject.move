module shareobject::shareobject{
    use std::string::{String};
    
    const EInvalidOwner: u64 = 1;

    public struct PermissionKeeper has key, store {
        id: UID,
        receiver: address,
        permissions_list: vector<String>,
    }

    public fun create_permission(
        permissions_list: vector<String>,
        receiver: address,
        ctx: &mut TxContext
    ) {
        let uid = object::new(ctx);
        let permission_wrapper = PermissionKeeper {
            id: uid,
            receiver:receiver,
            permissions_list,
        };

        transfer::share_object(permission_wrapper);
    }

    public fun add_permission(
        permission_wrapper: &mut PermissionKeeper,
        new_permissions: vector<String>
    ) {
        let mut i = 0;
        while (i < vector::length(&new_permissions)) {
            let permission = *vector::borrow(&new_permissions, i);
            vector::push_back(&mut permission_wrapper.permissions_list, permission);
            i = i + 1;
        }
    }

    public fun modify_permission(
        permission_wrapper: &mut PermissionKeeper,
        index: u64,
        new_permission: String
    ) {
        let len = vector::length(&permission_wrapper.permissions_list);
        assert!(index < len, EInvalidOwner);

        vector::swap_remove(&mut permission_wrapper.permissions_list, index);
        vector::push_back(&mut permission_wrapper.permissions_list, new_permission);
    }

    public fun remove_permission(
        permission_wrapper: &mut PermissionKeeper,
        index: u64
    ) {
        let len = vector::length(&permission_wrapper.permissions_list);
        assert!(index < len, EInvalidOwner);

        vector::swap_remove(&mut permission_wrapper.permissions_list, index);
    }


    

}
