//! Private core types.

use ::cryptoki::{Cryptoki, SessionFlags, SessionHandle, SessionInfo, SlotId,
                 UserType};
use ::error::*;

//------------ Core ---------------------------------------------------------

/// A private type wrapping a cryptoki value and a session handle.
///
/// Ownership of a value of this type is transferred between the various
/// types that represent the ongoing operations of a session.
pub struct Core {
    ck: Cryptoki,
    handle: SessionHandle,
}

impl Core {
    pub fn new(ck: Cryptoki, slot_id: SlotId, flags: SessionFlags)
               -> Result<Self, OpenSessionError> {
        let handle = ck.open_session(slot_id, flags)?;
        Ok(Core {
            ck: ck,
            handle: handle
        })
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // XXX We will have to ignore any error here. This may cause all
        //     sorts of trouble later, but, sadly, there ain’t nothing we
        //     can do. Or is there?
        let _ = self.ck.close_session(self.handle);
    }
}


/// # Session Functions
///
/// As a convenience, we wrap all Cryptoki functions that use a session
/// here.
impl Core {
    pub fn init_pin(&self, pin: Option<&str>) -> Result<(), SetPinError> {
        self.ck.init_pin(self.handle, pin).map_err(Into::into)
    }

    pub fn set_pin(&self, old_pin: Option<&str>, new_pin: Option<&str>)
                   -> Result<(), SetPinError> {
        self.ck.set_pin(self.handle, old_pin, new_pin).map_err(Into::into)
    }

    pub fn get_session_info(&self, info: &mut SessionInfo)
                            -> Result<(), SessionAccessError> {
        self.ck.get_session_info(self.handle, info).map_err(Into::into)
    }

    pub fn login(&self, user_type: UserType, pin: Option<&str>)
                 -> Result<(), LoginError> {
        self.ck.login(self.handle, user_type, pin).map_err(Into::into)
    }

    pub fn logout(&self) -> Result<(), LogoutError> {
        self.ck.logout(self.handle).map_err(Into::into)
    }
}

