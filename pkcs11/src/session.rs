
use ::ck::{Cryptoki, SessionFlags, SessionInfo, SlotId, UserType};
use ::error::*;
use super::core::Core;


//------------ Session -------------------------------------------------------

pub struct Session {
    core: Core,
}

impl Session {
    pub fn new(ck: Cryptoki, slot_id: SlotId, flags: SessionFlags)
               -> Result<Self, OpenSessionError> {
        Core::new(ck, slot_id, flags).map(|core| Session{core: core})
    }

    pub fn new_rw(ck: Cryptoki, slot_id: SlotId)
                  -> Result<Self, OpenSessionError> {
        Self::new(ck, slot_id, SessionFlags::rw_session())
    }

    pub fn new_row(ck: Cryptoki, slot_id: SlotId)
                   -> Result<Self, OpenSessionError> {
        Self::new(ck, slot_id, SessionFlags::default())
    }
}


impl Session {
    pub fn init_pin(&self, pin: Option<&str>) -> Result<(), SetPinError> {
        self.core.init_pin(pin)
    }

    pub fn set_pin(&self, old_pin: Option<&str>, new_pin: Option<&str>)
                   -> Result<(), SetPinError> {
        self.core.set_pin(old_pin, new_pin)
    }

    pub fn get_info(&self) -> Result<SessionInfo, SessionAccessError> {
        let mut info = SessionInfo::default();
        self.core.get_session_info(&mut info)?;
        Ok(info)
    }

    pub fn login(&self, user_type: UserType, pin: Option<&str>)
                 -> Result<(), LoginError> {
        self.core.login(user_type, pin)
    }

    pub fn logout(&self) -> Result<(), LogoutError> {
        self.core.logout()
    }
}

