
use pkcs11_sys as sys;
use super::TokenError;


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


//------------ State ---------------------------------------------------------

/// The session state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum State {
    RoPublicSession,
    RoUserFunctions,
    RwPublicSession,
    RwUserFunctions,
    RwSoFunctions,
}

impl State {
    pub fn try_from(state: sys::CK_STATE) -> Result<Self, TokenError> {
        match state {
            sys::CKS_RO_PUBLIC_SESSION => Ok(State::RoPublicSession),
            sys::CKS_RO_USER_FUNCTIONS => Ok(State::RoUserFunctions),
            sys::CKS_RW_PUBLIC_SESSION => Ok(State::RwPublicSession),
            sys::CKS_RW_USER_FUNCTIONS => Ok(State::RwUserFunctions),
            sys::CKS_RW_SO_FUNCTIONS => Ok(State::RwSoFunctions),
            _ => Err(TokenError::GeneralError),
        }
    }
}


//------------ UserType ------------------------------------------------------

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


