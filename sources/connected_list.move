// connected list consust of all the address that are connected to the admin
module shareobject::connected_list{
    
    const EInvalidOwner: u64 = 1;

    public struct ConnectedUserList has key, store {
        id: UID,
        owner: address,
        user_list: vector<address>,
    }



    public fun create_permission(
        user_list: vector<address>,
        owner: address,
        ctx: &mut TxContext
    ) {
        let uid = object::new(ctx);
        let connected_list = ConnectedUserList {
            id: uid,
            owner:owner,
            user_list,
        };

        transfer::share_object(connected_list);
    }

    public fun add_permission(
        connected_list: &mut ConnectedUserList,
        new_permissions: vector<address>
    ) {
        let mut i = 0;
        while (i < vector::length(&new_permissions)) {
            let permission = *vector::borrow(&new_permissions, i);
            vector::push_back(&mut connected_list.user_list, permission);
            i = i + 1;
        }
    }

    public fun modify_permission(
        connected_list: &mut ConnectedUserList,
        index: u64,
        new_permission: address
    ) {
        let len = vector::length(&connected_list.user_list);
        assert!(index < len, EInvalidOwner);

        vector::swap_remove(&mut connected_list.user_list, index);
        vector::push_back(&mut connected_list.user_list, new_permission);
    }

    public fun remove_permission(
        connected_list: &mut ConnectedUserList,
        index: u64
    ) {
        let len = vector::length(&connected_list.user_list);
        assert!(index < len, EInvalidOwner);

        vector::swap_remove(&mut connected_list.user_list, index);
    }

}
