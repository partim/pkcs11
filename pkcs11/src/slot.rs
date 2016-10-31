
use std::borrow::Cow;
use pkcs11_sys as sys;
use super::cryptoki::Cryptoki;
use super::error::Result;
use super::session::Session;


//------------ Slot ----------------------------------------------------------

pub struct Slot {
    ck: Cryptoki,
    id: sys::CK_SLOT_ID
}

impl Slot {
    pub fn new(ck: Cryptoki, id: sys::CK_SLOT_ID) -> Self {
        Slot{ck: ck, id: id}
    }

    pub fn id(&self) -> sys::CK_SLOT_ID {
        self.id
    }

    pub fn get_slot_info(&self) -> Result<SlotInfo> {
        let mut res = SlotInfo::default();
        try!(self.ck.get_slot_info(self.id, &mut res.info));
        Ok(res)
    }

    pub fn get_token_info(&self) -> Result<TokenInfo> {
        let mut res = TokenInfo::default();
        try!(self.ck.get_token_info(self.id, &mut res.info));
        Ok(res)
    }

    pub fn open_session(&self, read_write: bool) -> Result<Session> {
        Session::new(self.ck.clone(), self.id, read_write)
    }
}


//------------ SlotInfo ------------------------------------------------------

#[derive(Default)]
pub struct SlotInfo {
    info: sys::CK_SLOT_INFO
}

impl SlotInfo {
    pub fn slot_description(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.slotDescription)
    }

    pub fn manufacturer_id(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.manufacturerID)
    }

    pub fn hardware_version(&self) -> (u8, u8) {
        (self.info.hardwareVersion.major, self.info.hardwareVersion.minor)
    }

    pub fn firmware_version(&self) -> (u8, u8) {
        (self.info.firmwareVersion.major, self.info.firmwareVersion.minor)
    }

    pub fn is_token_present(&self) -> bool {
        self.info.flags & sys::CKF_TOKEN_PRESENT != 0
    }

    pub fn is_removable_device(&self) -> bool {
        self.info.flags & sys::CKF_REMOVABLE_DEVICE != 0
    }

    pub fn is_hw_slot(&self) -> bool {
        self.info.flags & sys::CKF_HW_SLOW != 0
    }
}


//------------ TokenInfo -----------------------------------------------------

#[derive(Default)]
pub struct TokenInfo {
    info: sys::CK_TOKEN_INFO
}

impl TokenInfo {
    pub fn label(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.label)
    }

    pub fn manufacturer(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.manufacturer)
    }

    pub fn model(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.model)
    }

    pub fn has_rng(&self) -> bool {
        self.info.flags & sys::CKF_RNG != 0
    }

    pub fn is_write_protected(&self) -> bool {
        self.info.flags & sys::CKF_WRITE_PROTECTED != 0
    }

    pub fn is_login_required(&self) -> bool {
        self.info.flags & sys::CKF_LOGIN_REQUIRED != 0
    }

    pub fn is_user_pin_initialized(&self) -> bool {
        self.info.flags & sys::CKF_USER_PIN_INITIALIZED != 0
    }

    // ...
}

