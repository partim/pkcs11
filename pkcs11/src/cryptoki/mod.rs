//! Safe wrappers for the Cryptoki API.

//============ Re-exports ====================================================
//
// These sub-modules only exist to keep the file size under control. Hence
// those glob imports.

pub use self::error::*;
pub use self::flags::*;
pub use self::structs::*;
pub use self::types::*;

mod error;
mod flags;
mod once;
mod structs;
mod types;


//============ Actual Content ================================================

use std::{iter, mem, ptr};
use std::sync::Arc;
use libloading::Library;
use pkcs11_sys as sys;
use self::once::CryptokiOnce;


//------------ Cryptoki ------------------------------------------------------

#[derive(Clone)]
pub struct Cryptoki {
    inner: Arc<CryptokiOnce>,
}

impl Cryptoki {
    pub fn new(lib: Library, args: Option<sys::CK_C_INITIALIZE_ARGS>)
               -> Result<Self, TokenError> {
        CryptokiOnce::new(lib, args).map(|ck| Cryptoki{inner: Arc::new(ck)})
    }
}


macro_rules! call_ck {
    ($slf:ident.$f:ident( $( $arg:expr ),* ) ) => {
        match ((*$slf.inner.ck()).$f)( $( $arg ),* ) {
            sys::CKR_OK => { }
            err => return Err(err.into())
        }
    }
}


impl Cryptoki {
    /// Obtains general information about Cryptoki.
    pub fn get_info(&self, info: &mut Info) -> Result<(), TokenError> {
        Ok(unsafe {
            call_ck!(self.C_GetInfo(info.as_mut()));
        })
    }

    /// Returns a list of all the valid slot IDs in the system.
    ///
    /// If `token_present` is `true`, only the IDs of slots that currently
    /// have a token present are returned.
    pub fn get_slot_list(&self, token_present: bool)
                         -> Result<Vec<SlotId>, TokenError> {
        let token_present = if token_present { sys::CK_TRUE }
                            else { sys::CK_FALSE };
        Ok(unsafe {
            let mut len = 0;
            call_ck!(self.C_GetSlotList(token_present, ptr::null_mut(),
                                        &mut len));
            let mut res = vec![0; from_ck_long(len)];
            call_ck!(self.C_GetSlotList(token_present, res.as_mut_ptr(),
                                        &mut len));
            res.truncate(from_ck_long(len));
            mem::transmute(res)
        })
    }

    /// Obtains information about a particular slot in the system.
    pub fn get_slot_info(&self, slot_id: SlotId, info: &mut SlotInfo)
                       -> Result<(), SlotAccessError> {
        Ok(unsafe {
            call_ck!(self.C_GetSlotInfo(slot_id.into(), info.as_mut()));
        })
    }

    /// Obtains information about a particular token in the system.
    pub fn get_token_info(&self, slot_id: SlotId, info: &mut TokenInfo)
                        -> Result<(), SlotAccessError> {
        Ok(unsafe {
            call_ck!(self.C_GetTokenInfo(slot_id.into(), info.as_mut()));
        })
    }

    /// Returns a list of the mechanism types supported by a token.
    pub fn get_mechanism_list<T>(&self, slot_id: SlotId)
                                 -> Result<T, SlotAccessError> 
                              where T: iter::FromIterator<MechanismType> {
        let vec = unsafe {
            let mut len = 0;
            call_ck!(self.C_GetMechanismList(slot_id.into(), ptr::null_mut(),
                                             &mut len));
            let mut res = vec![0; from_ck_long(len)];
            call_ck!(self.C_GetMechanismList(slot_id.into(), res.as_mut_ptr(),
                                             &mut len));
            res.truncate(from_ck_long(len));
            res
        };
        Ok(T::from_iter(vec.into_iter().map(MechanismType::from)))
    }

    /// Obtains information about a particular mechanism supported by a token.
    pub fn get_mechanism_info(&self, slot_id: SlotId,
                              mechanism: MechanismType,
                              info: &mut MechanismInfo)
                              -> Result<(), GetMechanismInfoError> {
        Ok(unsafe {
            call_ck!(self.C_GetMechanismInfo(slot_id.into(), mechanism.into(),
                                             info.as_mut()));
        })
    }

    /// Initializes a token.
    pub fn init_token(&self, slot_id: SlotId, pin: Option<&str>,
                    label: &str) -> Result<(), InitTokenError> {
        if label.as_bytes().len() != 32 {
            return Err(InitTokenError::LabelInvalid)
        }
        let (ptr, len) = translate_pin(pin);
        Ok(unsafe {
            call_ck!(self.C_InitToken(slot_id.into(), ptr, len,
                                      label.as_ptr()))
        })
    }

    /// Initializes the normal user’s PIN.
    pub fn init_pin(&self, session: SessionHandle, pin: Option<&str>)
                  -> Result<(), SetPinError> {
        let (ptr, len) = translate_pin(pin);
        Ok(unsafe {
            call_ck!(self.C_InitPIN(session.into(), ptr, len))
        })
    }

    /// Modifies the PIN of the user currently logged in.
    pub fn set_pin(&self, session: SessionHandle, old_pin: Option<&str>,
                   new_pin: Option<&str>) -> Result<(), SetPinError> {
        let (oldptr, oldlen) = translate_pin(old_pin);
        let (newptr, newlen) = translate_pin(new_pin);
        Ok(unsafe {
            call_ck!(self.C_SetPIN(session.into(), oldptr, oldlen,
                                   newptr, newlen))
        })
    }

    /// Opens a sessions between the application and a particular token.
    pub fn open_session(&self, slot_id: SlotId, flags: SessionFlags)
                        -> Result<SessionHandle, OpenSessionError> {
        // CKF_SERIAL_SESSION must always be set. Let’s do that here, then.
        let flags = flags | SessionFlags::serial_session();
        Ok(unsafe {
            let mut handle = 0;
            call_ck!(self.C_OpenSession(slot_id.into(), flags.into(),
                                        ptr::null(), None, &mut handle));
            handle.into()
        })
    }

    /// Closes a session between an application and a token.
    pub fn close_session(&self, session: SessionHandle)
                         -> Result<(), SessionAccessError> {
        Ok(unsafe { call_ck!(self.C_CloseSession(session.into())) })
    }

    /// Closes sessions an application has with a token in the given slot.
    pub fn close_all_sessions(&self, slot_id: SlotId)
                              -> Result<(), SlotAccessError> {
        Ok(unsafe { call_ck!(self.C_CloseAllSessions(slot_id.into())) })
    }

    /// Obtains information about a session.
    pub fn get_session_info(&self, session: SessionHandle,
                            info: &mut SessionInfo)
                            -> Result<(), SessionAccessError> {
        Ok(unsafe {
            call_ck!(self.C_GetSessionInfo(session.into(), info.as_mut()));
        })
    }

    /// Obtains a copy of the operational state of the session.
    pub fn get_operation_state(&self, session: SessionHandle,
                               state: Option<&mut [u8]>)
                               -> Result<usize, GetOperationStateError> {
        Ok(unsafe {
            let mut res = opt_len(&state);
            call_ck!(self.C_GetOperationState(session.into(),
                                              opt_mut_ptr(state), &mut res));
            from_ck_long(res)
        })
    }

    /// Restores the operational state of a session.
    pub fn set_operation_state(&self, session: SessionHandle,
                               operation_state: &[u8],
                               encryption_key: Option<ObjectHandle>,
                               authentication_key: Option<ObjectHandle>)
                               -> Result<(), SetOperationStateError> {
        let encryption_key = match encryption_key {
            Some(key) => key.into(),
            None => 0
        };
        let authentication_key = match authentication_key {
            Some(key) => key.into(),
            None => 0
        };
        Ok(unsafe { call_ck!(
            self.C_SetOperationState(session.into(), operation_state.as_ptr(),
                                     ck_len(operation_state),
                                     encryption_key,
                                     authentication_key)
        )})
    }

    /// Logs a user into a token.
    pub fn login(&self, session: SessionHandle, user_type: UserType,
                 pin: Option<&str>) -> Result<(), LoginError> {
        let (ptr, len) = match pin {
            Some(pin) => (pin.as_ptr(), ck_len(pin)),
            None => (ptr::null(), 0)
        };
        Ok(unsafe { call_ck!(
            self.C_Login(session.into(), user_type.into(), ptr, len)
        )})
    }

    /// Logs a user out from a token.
    pub fn logout(&self, session: SessionHandle) -> Result<(), LogoutError> {
        Ok(unsafe { call_ck!(self.C_Logout(session.into())) })
    }

    /// Creates a new object.
    pub fn create_object<'a, T>(&self, session: SessionHandle, template: T)
                                -> Result<ObjectHandle, CreateObjectError>
                         where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_CreateObject(session.into(), ptr, len, &mut res));
            res.into()
        })
    }

    /// Copies an object.
    pub fn copy_object<'a, T>(&self, session: SessionHandle,
                              object: ObjectHandle, template: T)
                              -> Result<ObjectHandle, CopyObjectError> 
                       where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_CopyObject(session.into(), object.into(), ptr,
                                       len, &mut res));
            res.into()
        })
    }

    /// Destroys an object.
    pub fn destroy_object(&self, session: SessionHandle, object: ObjectHandle)
                          -> Result<(), ObjectAccessError> {
        Ok(unsafe {
            call_ck!(self.C_DestroyObject(session.into(), object.into()))
        })
    }

    pub fn get_object_size(&self, session: SessionHandle,
                           object: ObjectHandle)
                           -> Result<usize, ObjectAccessError> {
        Ok(unsafe {
            let mut res = 0;
            call_ck!(self.C_GetObjectSize(session.into(), object.into(),
                                          &mut res));
            from_ck_long(res)
        })
    }

    pub fn get_attribute_value<'a, T>(&self, session: SessionHandle,
                                      object: ObjectHandle, mut template: T)
                                      -> Result<(), GetAttributeValueError>
                               where T: AsMut<[Attribute<'a>]> {
        Ok(unsafe {
            let template: &mut [sys::CK_ATTRIBUTE]
                = mem::transmute(template.as_mut());
            call_ck!(self.C_GetAttributeValue(session.into(), object.into(),
                                              template.as_mut_ptr(),
                                              ck_len(template)))
        })
    }

    pub fn set_attribute_value<'a, T>(&self, session: SessionHandle,
                                      object: ObjectHandle, template: T)
                                      -> Result<(), CopyObjectError>
                               where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_SetAttributeValue(session.into(), object.into(),
                                              ptr, len))
        })
    }

    pub fn find_objects_init<'a, T>(&self, session: SessionHandle,
                                    template: T)
                                    -> Result<(), FindObjectsInitError>
                             where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_FindObjectsInit(session.into(), ptr, len))
        })
    }

    pub fn find_objects(&self, session: SessionHandle,
                        buf: &mut [ObjectHandle])
                        -> Result<usize, ContinuationError> {
        Ok(unsafe {
            let mut res = 0;
            let mut buf: &mut [sys::CK_OBJECT_HANDLE] = mem::transmute(buf);
            call_ck!(self.C_FindObjects(session.into(), buf.as_mut_ptr(),
                                        ck_len(buf), &mut res));
            from_ck_long(res)
        })
    }

    pub fn find_objects_final(&self, session: SessionHandle)
                              -> Result<(), ContinuationError> {
        Ok(unsafe {
            call_ck!(self.C_FindObjectsFinal(session.into()))
        })
    }

    pub fn encrypt_init<P>(&self, session: SessionHandle,
                           mechanism: MechanismType, param: &P,
                           key: ObjectHandle)
                           -> Result<(), CryptoInitError> {
        Ok(unsafe {
            call_ck!(self.C_EncryptInit(session.into(),
                                        &init_mechanism(mechanism, param),
                                        key.into()))
        })
    }

    pub fn encrypt(&self, session: SessionHandle,
                   data: &[u8], encrypted_data: Option<&mut [u8]>)
                   -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_data);
            call_ck!(self.C_Encrypt(session.into(), data.as_ptr(), ck_len(data),
                                    opt_mut_ptr(encrypted_data), &mut res));
            from_ck_long(res)
        })
    }

    pub fn encrypt_update(&self, session: SessionHandle,
                          part: &[u8], encrypted_part: Option<&mut [u8]>)
                          -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_part);
            call_ck!(self.C_EncryptUpdate(session.into(), part.as_ptr(),
                                          ck_len(part),
                                          opt_mut_ptr(encrypted_part),
                                          &mut res));
            from_ck_long(res)
        })
    }

    pub fn encrypt_final(&self, session: SessionHandle,
                         last_encrypted_part: Option<&mut [u8]>)
                         -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&last_encrypted_part);
            call_ck!(self.C_EncryptFinal(session.into(),
                                         opt_mut_ptr(last_encrypted_part),
                                         &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_init<P>(&self, session: SessionHandle,
                        mechanism: MechanismType, param: &P,
                        key: ObjectHandle) -> Result<(), CryptoInitError> {
        Ok(unsafe {
            call_ck!(self.C_DecryptInit(session.into(),
                                        &init_mechanism(mechanism, param),
                                        key.into()))
        })
    }

    pub fn decrypt(&self, session: SessionHandle,
                   encrypted_data: &[u8], data: Option<&mut [u8]>)
                   -> Result<usize, CiphertextError> {
        Ok(unsafe {
            let mut res = opt_len(&data);
            call_ck!(self.C_Decrypt(session.into(), encrypted_data.as_ptr(),
                                    ck_len(encrypted_data),
                                    opt_mut_ptr(data), &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_update(&self, session: SessionHandle,
                          encrypted_part: &[u8], part: Option<&mut [u8]>)
                          -> Result<usize, CiphertextError> {
        Ok(unsafe {
            let mut res = opt_len(&part);
            call_ck!(self.C_DecryptUpdate(session.into(),
                                          encrypted_part.as_ptr(),
                                          ck_len(encrypted_part),
                                          opt_mut_ptr(part), &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_final(&self, session: SessionHandle,
                         last_part: Option<&mut [u8]>)
                         -> Result<usize, CiphertextError> {
        Ok(unsafe {
            let mut res = opt_len(&last_part);
            call_ck!(self.C_DecryptFinal(session.into(),
                                         opt_mut_ptr(last_part),
                                         &mut res));
            from_ck_long(res)
        })
    }

    pub fn digest_init<P>(&self, session: SessionHandle,
                       mechanism: MechanismType, param: &P)
                       -> Result<(), DigestInitError> {
        Ok(unsafe {
            call_ck!(self.C_DigestInit(session.into(),
                                       &init_mechanism(mechanism, param)))
        })
    }

    pub fn digest(&self, session: SessionHandle,
                  data: &[u8], digest: Option<&mut [u8]>)
                  -> Result<usize, DigestError> {
        Ok(unsafe {
            let mut res = opt_len(&digest);
            call_ck!(self.C_Digest(session.into(), data.as_ptr(), ck_len(data),
                                   opt_mut_ptr(digest), &mut res));
            from_ck_long(res)
        })
    }

    pub fn digest_update(&self, session: SessionHandle,
                         part: &[u8]) -> Result<(), ContinuationError> {
        Ok(unsafe {
            call_ck!(self.C_DigestUpdate(session.into(), part.as_ptr(),
                                         ck_len(part)))
        })
    }

    pub fn digest_key(&self, session: SessionHandle,
                      key: ObjectHandle) -> Result<(), DigestKeyError> {
        Ok(unsafe { call_ck!(self.C_DigestKey(session.into(), key.into())) })
    }

    pub fn digest_final(&self, session: SessionHandle,
                        digest: Option<&mut [u8]>)
                        -> Result<usize, DigestError> {
        Ok(unsafe {
            let mut res = opt_len(&digest);
            call_ck!(self.C_DigestFinal(session.into(), opt_mut_ptr(digest),
                                        &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_init<P>(&self, session: SessionHandle,
                        mechanism: MechanismType, param: &P,
                        key: ObjectHandle) -> Result<(), CryptoInitError> {
        Ok(unsafe {
            call_ck!(self.C_SignInit(session.into(),
                                     &init_mechanism(mechanism, param),
                                     key.into()))
        })
    }

    pub fn sign(&self, session: SessionHandle,
                data: &[u8], signature: Option<&mut [u8]>)
                -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&signature);
            call_ck!(self.C_Sign(session.into(), data.as_ptr(), ck_len(data),
                                 opt_mut_ptr(signature), &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_update(&self, session: SessionHandle,
                       part: &[u8]) -> Result<(), PlaintextUpdateError> {
        Ok(unsafe {
            call_ck!(self.C_SignUpdate(session.into(), part.as_ptr(),
                                       ck_len(part)));
        })
    }

    pub fn sign_final(&self, session: SessionHandle,
                      signature: Option<&mut [u8]>)
                      -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&signature);
            call_ck!(self.C_SignFinal(session.into(), opt_mut_ptr(signature),
                                      &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_recover_init<P>(&self, session: SessionHandle,
                                mechanism: MechanismType, param: &P,
                                key: ObjectHandle)
                                -> Result<(), CryptoInitError> {
        Ok(unsafe {
            call_ck!(self.C_SignRecoverInit(session.into(),
                                            &init_mechanism(mechanism, param),
                                            key.into()))
        })
    }

    pub fn sign_recover(&self, session: SessionHandle,
                        data: &[u8], signature: Option<&mut [u8]>)
                        -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&signature);
            call_ck!(self.C_SignRecover(session.into(), data.as_ptr(),
                                        ck_len(data), opt_mut_ptr(signature),
                                        &mut res));
            from_ck_long(res)
        })
    }

    pub fn verify_init<P>(&self, session: SessionHandle,
                          mechanism: MechanismType, param: &P,
                          key: ObjectHandle) -> Result<(), CryptoInitError> {
        Ok(unsafe {
            call_ck!(self.C_VerifyInit(session.into(),
                                       &init_mechanism(mechanism, param),
                                       key.into()))
        })
    }

    pub fn verify(&self, session: SessionHandle,
                  data: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        Ok(unsafe {
            call_ck!(self.C_Verify(session.into(), data.as_ptr(), ck_len(data),
                                   signature.as_ptr(), ck_len(signature)))
        })
    }
                                        
    pub fn verify_update(&self, session: SessionHandle,
                         data: &[u8]) -> Result<(), PlaintextUpdateError> {
        Ok(unsafe {
            call_ck!(self.C_VerifyUpdate(session.into(), data.as_ptr(),
                                         ck_len(data)))
        })
    }

    pub fn verify_final(&self, session: SessionHandle,
                        signature: &[u8]) -> Result<(), VerifyError> {
        Ok(unsafe {
            call_ck!(self.C_VerifyFinal(session.into(), signature.as_ptr(),
                                        ck_len(signature)))
        })
    }

    pub fn verify_recover_init<P>(&self, session: SessionHandle,
                                  mechanism: MechanismType, param: &P,
                                  key: ObjectHandle)
                                  -> Result<(), CryptoInitError> {
        Ok(unsafe {
            call_ck!(self.C_VerifyRecoverInit(session.into(),
                                              &init_mechanism(mechanism,
                                                              param),
                                              key.into()))
        })
    }

    pub fn verify_recover(&self, session: SessionHandle,
                          signature: &[u8], data: Option<&mut [u8]>)
                          -> Result<usize, VerifyRecoverError> {
        Ok(unsafe {
            let mut res = opt_len(&data);
            call_ck!(self.C_VerifyRecover(session.into(), signature.as_ptr(),
                                          ck_len(signature),
                                          opt_mut_ptr(data), &mut res));
            from_ck_long(res)
        })
    }

    pub fn digest_encrypt_update(&self, session: SessionHandle,
                                 part: &[u8],
                                 encrypted_part: Option<&mut [u8]>)
                                 -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_part);
            call_ck!(self.C_DigestEncryptUpdate(session.into(), part.as_ptr(),
                                                ck_len(part),
                                                opt_mut_ptr(encrypted_part),
                                                &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_digest_update(&self, session: SessionHandle,
                                 encrypted_part: &[u8],
                                 part: Option<&mut [u8]>)
                                 -> Result<usize, CiphertextError> {
        Ok(unsafe {
            let mut res = opt_len(&part);
            call_ck!(self.C_DecryptDigestUpdate(session.into(),
                                                encrypted_part.as_ptr(),
                                                ck_len(encrypted_part),
                                                opt_mut_ptr(part), &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_encrypt_update(&self, session: SessionHandle,
                               part: &[u8],
                               encrypted_part: Option<&mut [u8]>)
                               -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_part);
            call_ck!(self.C_SignEncryptUpdate(session.into(), part.as_ptr(),
                                              ck_len(part),
                                              opt_mut_ptr(encrypted_part),
                                              &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_verify_update(&self, session: SessionHandle,
                                 encrypted_part: &[u8],
                                 part: Option<&mut [u8]>)
                                 -> Result<usize, PlaintextError> {
        Ok(unsafe {
            let mut res = opt_len(&part);
            call_ck!(self.C_DecryptVerifyUpdate(session.into(),
                                                encrypted_part.as_ptr(),
                                                ck_len(encrypted_part),
                                                opt_mut_ptr(part), &mut res));
            from_ck_long(res)
        })
    }

    pub fn generate_key<'a, T>(&self, session: SessionHandle,
                               mechanism: &sys::CK_MECHANISM, template: T)
                               -> Result<ObjectHandle, CreateKeyError>
                        where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_GenerateKey(session.into(), mechanism, ptr, len,
                                        &mut res));
            res.into()
        })
    }

    /// Returns (public, private).
    pub fn generate_key_pair<'a, T, U>(&self, session: SessionHandle,
                                       mechanism: &sys::CK_MECHANISM,
                                       public_key_template: T,
                                       private_key_template: U)
                                       -> Result<(ObjectHandle,
                                                  ObjectHandle),
                                                 CreateKeyError>
                             where T: AsRef<[Attribute<'a>]>,
                                   U: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = (0, 0);
            let (pub_ptr, pub_len) = translate_template(public_key_template);
            let (prv_ptr, prv_len) = translate_template(private_key_template);
            call_ck!(self.C_GenerateKeyPair(session.into(), mechanism,
                                            pub_ptr, pub_len,
                                            prv_ptr, prv_len,
                                            &mut res.0, &mut res.1));
            (res.0.into(), res.1.into())
        })
    }

    pub fn wrap_key(&self, session: SessionHandle,
                    mechanism: &sys::CK_MECHANISM,
                    wrapping_key: ObjectHandle,
                    key: ObjectHandle,
                    wrapped_key: Option<&mut [u8]>)
                    -> Result<usize, WrapKeyError> {
        Ok(unsafe {
            let mut res = opt_len(&wrapped_key);
            call_ck!(self.C_WrapKey(session.into(), mechanism,
                                    wrapping_key.into(), key.into(),
                                    opt_mut_ptr(wrapped_key), &mut res));
            from_ck_long(res)
        })
    }

    pub fn unwrap_key<'a, T>(&self, session: SessionHandle,
                             mechanism: &sys::CK_MECHANISM,
                             unwrapping_key: ObjectHandle,
                             wrapped_key: &[u8], template: T)
                             -> Result<ObjectHandle, UnwrapKeyError>
                      where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_UnwrapKey(session.into(), mechanism,
                                      unwrapping_key.into(),
                                      wrapped_key.as_ptr(),
                                      ck_len(wrapped_key), ptr, len,
                                      &mut res));
            res.into()
        })
    }

    pub fn derive_key<'a, T>(&self, session: SessionHandle,
                             mechanism: &sys::CK_MECHANISM,
                             base_key: ObjectHandle, template: T)
                             -> Result<ObjectHandle, DeriveKeyError>
                      where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_DeriveKey(session.into(), mechanism,
                                      base_key.into(),
                                      ptr, len, &mut res));
            res.into()
        })
    }

    pub fn seed_random(&self, session: SessionHandle, seed: &[u8])
                       -> Result<(), SeedRandomError> {
        Ok(unsafe {
            call_ck!(self.C_SeedRandom(session.into(), seed.as_ptr(),
                                       ck_len(seed)))
        })
    }

    pub fn generate_random(&self, session: SessionHandle,
                           random_data: &mut [u8])
                           -> Result<(), GenerateRandomError> {
        Ok(unsafe {
            call_ck!(self.C_GenerateRandom(session.into(),
                                           random_data.as_mut_ptr(),
                                           ck_len(random_data)))
        })
    }
}


//------------ Helpers -------------------------------------------------------

fn ck_len<T, R: AsRef<[T]>>(r: R) -> sys::CK_ULONG {
    to_ck_long(r.as_ref().len())
}


/// Converts a `usize` to a `CK_ULONG`.
///
/// # Panics 
///
/// On some targets (such as 64 bit Windows), `CK_ULONG` is 32 bits while
/// `usize` is 64 bits. On these systems, the function will panic if given
/// a value that is too large.
#[inline(always)]
fn to_ck_long(x: usize) -> sys::CK_ULONG {
    // XXX Does this get optimized away if both types are identical?
    assert!(x <= sys::CK_ULONG_MAX as usize);
    x as sys::CK_ULONG
}

/// Converts a `CK_ULONG` into a `usize`.
///
/// # Assumption
///
/// Since `CK_ULONG` is equal to C’s `unsigned long int`, it should never
/// be bigger than the target’s pointer size and a cast should be safe.
#[inline(always)]
fn from_ck_long(x: sys::CK_ULONG) -> usize {
    x as usize
}

fn opt_len<T, R: AsRef<[T]>>(r: &Option<R>) -> sys::CK_ULONG {
    match *r {
        Some(ref r) => ck_len(r.as_ref()),
        None => 0
    }
}

fn opt_mut_ptr<T, R: AsMut<[T]>>(r: Option<R>) -> *mut T {
    match r {
        Some(mut r) => r.as_mut().as_mut_ptr(),
        None => ptr::null_mut()
    }
}

unsafe fn translate_template<'a, T>(t: T) -> (*const sys::CK_ATTRIBUTE,
                                              sys::CK_ULONG)
                             where T: AsRef<[Attribute<'a>]> {
    let template: &[sys::CK_ATTRIBUTE] = mem::transmute(t.as_ref());
    (template.as_ptr(), ck_len(template))
}

fn translate_pin(pin: Option<&str>)
                 -> (*const sys::CK_UTF8CHAR, sys::CK_ULONG) {
    match pin {
        Some(pin) => (pin.as_ptr(), ck_len(pin)),
        None => (ptr::null(), 0)
    }
}

fn init_mechanism<P>(mechanism: MechanismType, param: &P)
                     -> sys::CK_MECHANISM {
    sys::CK_MECHANISM {
        mechanism: mechanism.into(),
        pParameter: param as *const P as *const sys::CK_VOID,
        ulParameterLen: to_ck_long(mem::size_of::<P>())
    }
}

