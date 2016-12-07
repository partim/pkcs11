
use pkcs11_sys as sys;


//============ Newtypes for Opaque Types =====================================
 

//------------ SlotId --------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct SlotId(sys::CK_SLOT_ID);

impl From<sys::CK_SLOT_ID> for SlotId {
    fn from(id: sys::CK_SLOT_ID) -> Self {
        SlotId(id)
    }
}

impl From<SlotId> for sys::CK_SLOT_ID {
    fn from(id: SlotId) -> Self {
        id.0
    }
}


//------------ SessionHandle -------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct SessionHandle(sys::CK_SESSION_HANDLE);

impl From<sys::CK_SESSION_HANDLE> for SessionHandle {
    fn from(handle: sys::CK_SESSION_HANDLE) -> Self {
        SessionHandle(handle)
    }
}

impl From<SessionHandle> for sys::CK_SESSION_HANDLE {
    fn from(handle: SessionHandle) -> Self {
        handle.0
    }
}


//------------ ObjectHandle --------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct ObjectHandle(sys::CK_OBJECT_HANDLE);

impl From<sys::CK_OBJECT_HANDLE> for ObjectHandle {
    fn from(handle: sys::CK_OBJECT_HANDLE) -> Self {
        ObjectHandle(handle)
    }
}

impl From<ObjectHandle> for sys::CK_OBJECT_HANDLE {
    fn from(handle: ObjectHandle) -> Self {
        handle.0
    }
}


//============ Enums for De-facto Enums ======================================

/// The types of users for trying to log into a token.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UserType {
    /// The security officer.
    So,

    /// A normal user.
    User,

    /// Context specific user.
    ContextSpecific,
}

impl From<UserType> for sys::CK_USER_TYPE {
    fn from(value: UserType) -> Self {
        match value {
            UserType::So => sys::CKU_SO,
            UserType::User => sys::CKU_USER,
            UserType::ContextSpecific => sys::CKU_CONTEXT_SPECIFIC,
        }
    }
}


//============ Newtypes for Identifying Types ================================
//
// These are here for now in order to get rid of the `sys::CK_` prefix and the
// terrible upper case. Ultimately, we want to provide a sane way to
// initialize these from known values through some sort of enum.
//
// One more advantage of having newtypes is that we have separate types for
// the separate purposes instead of just lots of type aliases all ending up
// with `sys::CK_ULONG`.

//------------ MechanismType -------------------------------------------------

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct MechanismType(sys::CK_MECHANISM_TYPE);

impl From<sys::CK_MECHANISM_TYPE> for MechanismType {
    fn from(value: sys::CK_MECHANISM_TYPE) -> Self {
        MechanismType(value)
    }
}

impl From<MechanismType> for sys::CK_MECHANISM_TYPE {
    fn from(value: MechanismType) -> Self {
        value.0
    }
}



