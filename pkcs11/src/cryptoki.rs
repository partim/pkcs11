//! Safe wrappers for the Cryptoki API.

use std::{iter, mem, ptr, slice};
use std::marker::PhantomData;
use std::sync::Arc;
use libloading::{Library, Symbol};
use pkcs11_sys as sys;
use super::error::{KeyError, MechanismError, PermissionError, SessionError,
                   TemplateError, TokenError};


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
        match ((*$slf.inner.ck).$f)( $( $arg ),* ) {
            sys::CKR_OK => { }
            err => return Err(err.into())
        }
    }
}


impl Cryptoki {
    pub fn get_info(&self, info: &mut sys::CK_INFO)
                    -> Result<(), TokenError> {
        Ok(unsafe {
            call_ck!(self.C_GetInfo(info));
        })
    }

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

    pub fn get_slot_info(&self, slot_id: SlotId,
                         info: &mut sys::CK_SLOT_INFO)
                       -> Result<(), SlotAccessError> {
        Ok(unsafe {
            call_ck!(self.C_GetSlotInfo(slot_id.into(), info));
        })
    }

    pub fn get_token_info(&self, slot_id: SlotId,
                          info: &mut sys::CK_TOKEN_INFO)
                        -> Result<(), SlotAccessError> {
        Ok(unsafe {
            call_ck!(self.C_GetTokenInfo(slot_id.into(), info));
        })
    }

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

    pub fn get_mechanism_info(&self, slot_id: SlotId,
                              mechanism: MechanismType,
                              info: &mut sys::CK_MECHANISM_INFO)
                              -> Result<(), GetMechanismInfoError> {
        Ok(unsafe {
            call_ck!(self.C_GetMechanismInfo(slot_id.into(), mechanism.into(),
                                             info));
        })
    }

    pub fn init_token(&self, slot_id: SlotId, pin: &str,
                    label: &str) -> Result<(), InitTokenError> {
        if label.as_bytes().len() != 32 {
            return Err(InitTokenError::LabelIncorrect)
        }
        Ok(unsafe {
            call_ck!(self.C_InitToken(slot_id.into(), pin.as_ptr(),
                                      ck_len(pin), label.as_ptr()))
        })
    }

    pub fn init_pin(&self, session: SessionHandle, pin: &str)
                  -> Result<(), SetPinError> {
        Ok(unsafe {
            call_ck!(self.C_InitPIN(session.into(), pin.as_ptr(), ck_len(pin)))
        })
    }

    pub fn set_pin(&self, session: SessionHandle, old_pin: &str,
                 new_pin: &str) -> Result<(), SetPinError> {
        Ok(unsafe {
            call_ck!(self.C_SetPIN(session.into(), old_pin.as_ptr(),
                                   ck_len(old_pin), new_pin.as_ptr(),
                                   ck_len(new_pin)))
        })
    }

    pub fn open_session(&self, slot_id: SlotId, flags: sys::CK_FLAGS,
                        app: *const sys::CK_VOID,
                        notify: Option<sys::CK_NOTIFY>)
                        -> Result<SessionHandle, OpenSessionError> {
        Ok(unsafe {
            let mut handle = 0;
            call_ck!(self.C_OpenSession(slot_id.into(), flags, app, notify,
                                        &mut handle));
            handle.into()
        })
    }

    pub fn close_session(&self, session: SessionHandle)
                         -> Result<(), SessionAccessError> {
        Ok(unsafe { call_ck!(self.C_CloseSession(session.into())) })
    }

    pub fn close_all_sessions(&self, slot_id: SlotId)
                              -> Result<(), SlotAccessError> {
        Ok(unsafe { call_ck!(self.C_CloseAllSessions(slot_id.into())) })
    }

    pub fn get_session_info(&self, session: SessionHandle,
                            info: &mut sys::CK_SESSION_INFO)
                            -> Result<(), SessionAccessError> {
        Ok(unsafe {
            call_ck!(self.C_GetSessionInfo(session.into(), info));
        })
    }

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

    pub fn logout(&self, session: SessionHandle) -> Result<(), LogoutError> {
        Ok(unsafe { call_ck!(self.C_Logout(session.into())) })
    }

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

fn init_mechanism<P>(mechanism: MechanismType, param: &P)
                     -> sys::CK_MECHANISM {
    sys::CK_MECHANISM {
        mechanism: mechanism.into(),
        pParameter: param as *const P as *const sys::CK_VOID,
        ulParameterLen: to_ck_long(mem::size_of::<P>())
    }
}


//------------ CryptokiOnce --------------------------------------------------

struct CryptokiOnce {
    /// The library this Cryptoki implementation came from.
    ///
    /// We only hold onto it here so that it doesn’t get unloaded while we
    /// need it. Normally, we would keep the `Symbol` loaded from it, but we
    /// only need that to get the function list. So we rather keep the
    /// library and the raw function list.
    #[allow(dead_code)]
    library: Library,

    /// The function list retrieved from the library.
    ck: *const sys::CK_FUNCTION_LIST,
}

impl CryptokiOnce {
    fn new(lib: Library, args: Option<sys::CK_C_INITIALIZE_ARGS>)
            -> Result<Self, TokenError> {
        let ck = unsafe {
            let get_list: Symbol<sys::CK_C_GetFunctionList> =
                                        match lib.get(b"C_GetFunctionList") {
                Ok(list) => list,
                Err(_) => return Err(sys::CKR_GENERAL_ERROR.into())
            };
            let mut list = ptr::null();
            let res = get_list(&mut list);
            if res != sys::CKR_OK {
                return Err(res.into())
            }
            let args_ptr = match args {
                Some(args) => mem::transmute(&args),
                None => ptr::null()
            };
            let res = ((*list).C_Initialize)(args_ptr);
            // Getting "already initialized" is fine. We can use the same
            // module more than once ...
            if res != sys::CKR_OK &&
               res != sys::CKR_CRYPTOKI_ALREADY_INITIALIZED{
                return Err(res.into())
            }
            list
        };
        Ok(CryptokiOnce{library: lib, ck: ck})
    }
}

impl Drop for CryptokiOnce {
    fn drop(&mut self) {
        unsafe {
            ((*self.ck).C_Finalize)(ptr::null());
        }
    }
}


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


//============ Structures ====================================================

//------------ Attribute ----------------------------------------------------

pub struct Attribute<'a> {
    inner: sys::CK_ATTRIBUTE,
    marker: PhantomData<&'a u8>,
}

/// # Creation
///
impl<'a> Attribute<'a> {
    fn new<T: ?Sized>(attr: sys::CK_ATTRIBUTE_TYPE, ptr: *const T, len: usize)
                      -> Self {
        Attribute {
            inner: sys::CK_ATTRIBUTE {
                aType: attr,
                pValue: ptr as *const _,
                ulValueLen: to_ck_long(len)
            },
            marker: PhantomData
        }
    }

    pub fn from_none(attr: sys::CK_ATTRIBUTE_TYPE) -> Self {
        Self::new(attr, ptr::null() as *const u8, 0)
    }

    pub fn from_ref<T>(attr: sys::CK_ATTRIBUTE_TYPE, val: &'a T) -> Self {
        Self::new(attr, val, mem::size_of::<T>())
    }

    pub fn from_bytes(attr: sys::CK_ATTRIBUTE_TYPE, value: &'a [u8]) -> Self {
        Self::new(attr, value.as_ptr(), value.len())
    }
}

/// # Access to Data
///
impl<'a> Attribute<'a> {
    pub fn len(&self) -> Option<usize> {
        if self.inner.ulValueLen == sys::CK_UNAVAILABLE_INFORMATION {
            None
        }
        else {
            Some(from_ck_long(self.inner.ulValueLen))
        }
    }

    pub fn bytes(&self) -> Option<&'a [u8]> {
        if self.inner.pValue == ptr::null() {
            None
        }
        else {
            self.len().map(|len| unsafe {
                slice::from_raw_parts(mem::transmute(self.inner.pValue), len)
            })
        }
    }

    pub fn value<T>(&self) -> Option<&T> {
        self.len().map(|len| unsafe {
            assert_eq!(mem::size_of::<T>(), len);
            mem::transmute(self.inner.pValue)
        })
    }

    pub fn value_mut<T>(&mut self) -> Option<&mut T> {
        self.len().map(|len| unsafe {
            assert_eq!(mem::size_of::<T>(), len);
            mem::transmute(self.inner.pValue)
        })
    }
}


//============ Method-specific Errors ========================================

//------------ SlotAccessError -----------------------------------------------

/// An error happened during functions that query slot-related information.
#[derive(Copy, Clone)]
pub enum SlotAccessError {
    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// A token error occured.
    Token(TokenError)
}

impl From<sys::CK_RV> for SlotAccessError {
    fn from(err: sys::CK_RV) -> Self {
        match err {
            sys::CKR_SLOT_ID_INVALID => SlotAccessError::SlotIdInvalid,
            _ => SlotAccessError::Token(err.into())
        }
    }
}


//------------ GetMechanismInfoError -----------------------------------------

/// An error happened during the `Cryptoki::get_mechanism_info()` method.
#[derive(Copy, Clone)]
pub enum GetMechanismInfoError {
    /// The mechanism type given is not supported by the token.
    InvalidMechanism,

    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// A token error occured.
    Token(TokenError)
}

impl From<sys::CK_RV> for GetMechanismInfoError {
    fn from(err: sys::CK_RV) -> Self {
        match err {
            sys::CKR_MECHANISM_INVALID
                => GetMechanismInfoError::InvalidMechanism,
            sys::CKR_SLOT_ID_INVALID => GetMechanismInfoError::SlotIdInvalid,
            _ => GetMechanismInfoError::Token(err.into())
        }
    }
}


//------------ InitTokenError -----------------------------------------------

/// An error happened during the `Cryptoki::init_token()` method.
#[derive(Copy, Clone)]
pub enum InitTokenError {
    /// The label is not exactly 32 bytes long.
    LabelIncorrect,

    /// The specified PIN does not match the PIN stored in the token.
    PinIncorrect,

    /// The PIN is locked, e.g. after too many failed attempts.
    PinLocked,

    /// The token cannot be initialized because a session with it exists.
    SessionExists,

    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// The token cannot be initialized because it is write-protected.
    TokenWriteProtected,

    /// A token error occured.
    Token(TokenError)
}

impl From<sys::CK_RV> for InitTokenError {
    fn from(err: sys::CK_RV) -> Self {
        match err {
            sys::CKR_PIN_INCORRECT => InitTokenError::PinIncorrect,
            sys::CKR_PIN_LOCKED => InitTokenError::PinLocked,
            sys::CKR_SESSION_EXISTS => InitTokenError::SessionExists,
            sys::CKR_SLOT_ID_INVALID => InitTokenError::SlotIdInvalid,
            sys::CKR_TOKEN_WRITE_PROTECTED
                => InitTokenError::TokenWriteProtected,
            _ => InitTokenError::Token(err.into())
        }
    }
}


//------------ SetPinError --------------------------------------------------

/// An error happened while initializing or setting a PIN.
#[derive(Clone, Copy)]
pub enum SetPinError {
    /// The specified PIN has invalid characters in it.
    PinInvalid,

    /// The specified PIN does not match the PIN stored in the token.
    PinIncorrect,

    /// The specified PIN is too long or too short.
    PinLenRange,

    /// The PIN is locked, e.g. after too many failed attempts.
    PinLocked,

    /// A read-only error occurred.
    Permission(PermissionError),

    /// A session error occurred.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for SetPinError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            SetPinError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            SetPinError::Session(err)
        }
        else {
            match err {
                sys::CKR_PIN_INVALID => SetPinError::PinInvalid,
                sys::CKR_PIN_INCORRECT => SetPinError::PinIncorrect,
                sys::CKR_PIN_LEN_RANGE => SetPinError::PinLenRange,
                sys::CKR_PIN_LOCKED => SetPinError::PinLocked,
                _ => SetPinError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ OpenSessionError ----------------------------------------------

/// An error happened while opening a session.
#[derive(Clone, Copy)]
pub enum OpenSessionError {
    /// Either too many sessions or too many read/write sessions already open.
    SessionCount,
    
    /// A read/write SO session already exists.
    ///
    /// This prevents any further read-only sessions.
    SessionReadWriteSoExists,

    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// A read-only error occurred.
    Permission(PermissionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for OpenSessionError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            OpenSessionError::Permission(err)
        }
        else {
            match err {
                sys::CKR_SESSION_COUNT => OpenSessionError::SessionCount,
                sys::CKR_SESSION_READ_WRITE_SO_EXISTS
                    => OpenSessionError::SessionReadWriteSoExists,
                sys::CKR_SLOT_ID_INVALID => OpenSessionError::SlotIdInvalid,
                _ => OpenSessionError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ SessionAccessError --------------------------------------------

/// An error happened when closing a session.
#[derive(Copy, Clone)]
pub enum SessionAccessError {
    /// A session error occurred.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError),
}

impl From<sys::CK_RV> for SessionAccessError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            SessionAccessError::Session(err)
        }
        else {
            SessionAccessError::Token(TokenError::from(err))
        }
    }
}


//------------ GetOperationStateError ---------------------------------------

/// An error happened when trying to get the operation state.
#[derive(Clone, Copy)]
pub enum GetOperationStateError {
    /// The output is too large to fit in the supplied buffer.
    BufferTooSmall,

    /// There is no operation ongoing that would allow saving state.
    OperationNotInitialized,

    /// The operation state cannot be saved for some reason.
    StateUnsaveable,

    /// A session error occured.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for GetOperationStateError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            GetOperationStateError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL
                    => GetOperationStateError::BufferTooSmall,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => GetOperationStateError::OperationNotInitialized,
                sys::CKR_STATE_UNSAVEABLE
                    => GetOperationStateError::StateUnsaveable,
                _ => GetOperationStateError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ SetOperationStateError ---------------------------------------

/// An error happened while trying to set the operation state.
#[derive(Clone, Copy)]
pub enum SetOperationStateError {
    /// One of the keys specified is not the one used in the saved session.
    KeyChanged,

    /// One or both keys need to be supplied.
    KeyNeeded,

    /// An extraneous key was supplied.
    KeyNotNeeded,

    /// The supplied saved cryptographic operations state is invalid.
    SavedStateInvalid,

    /// A session error has occurred.
    Session(SessionError),

    /// A token error has occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for SetOperationStateError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            SetOperationStateError::Session(err)
        }
        else {
            match err {
                sys::CKR_KEY_CHANGED => SetOperationStateError::KeyChanged,
                sys::CKR_KEY_NEEDED => SetOperationStateError::KeyNeeded,
                sys::CKR_KEY_NOT_NEEDED
                    => SetOperationStateError::KeyNotNeeded,
                sys::CKR_SAVED_STATE_INVALID
                    => SetOperationStateError::SavedStateInvalid,
                _ => SetOperationStateError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ LoginError ---------------------------------------------------

/// An error has occurred whil trying to log in.
// XXX Might be useful to break this into temporary and permanent errors.
#[derive(Clone, Copy)]
pub enum LoginError {
    /// A context specific login was not properly prepared.
    OperationNotInitialized,

    /// The specified PIN does not match the PIN stored in the token.
    PinIncorrect,

    /// The PIN is locked, e.g. after too many failed attempts.
    PinLocked,

    /// A read-only is open preventing the SO to log in.
    SessionReadOnlyExists,

    /// The specified user is already logged in.
    UserAlreadyLoggedIn,

    /// Another user is already logged in preventing this user to log in.
    UserAnotherAlreadyLoggedIn,

    /// The normal user’s PIN has not yet been initialized.
    UserPinNotInitialized,

    /// An attempt was made to have more distinct users simultaneously
    /// logged into the token than the token and/or library permits.
    UserTooManyTypes,

    /// A session error has occurred.
    Session(SessionError),

    /// A token error has occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for LoginError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            LoginError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => LoginError::OperationNotInitialized,
                sys::CKR_PIN_INCORRECT => LoginError::PinIncorrect,
                sys::CKR_PIN_LOCKED => LoginError::PinLocked,
                sys::CKR_SESSION_READ_ONLY_EXISTS
                    => LoginError::SessionReadOnlyExists,
                sys::CKR_USER_ALREADY_LOGGED_IN
                    => LoginError::UserAlreadyLoggedIn,
                sys::CKR_USER_ANOTHER_ALREADY_LOGGED_IN
                    => LoginError::UserAnotherAlreadyLoggedIn,
                sys::CKR_USER_PIN_NOT_INITIALIZED
                    => LoginError::UserPinNotInitialized,
                sys::CKR_USER_TOO_MANY_TYPES => LoginError::UserTooManyTypes,
                _ => LoginError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ LogoutError ---------------------------------------------------

/// An error happened while logging out.
#[derive(Clone, Copy)]
pub enum LogoutError {
    /// A user is not logged in.
    UserNotLoggedIn,

    /// A session error occurred.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for LogoutError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            LogoutError::Session(err)
        }
        else {
            match err {
                sys::CKR_USER_NOT_LOGGED_IN => LogoutError::UserNotLoggedIn,
                _ => LogoutError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ CreateObjectError ---------------------------------------------

/// An error happened when creating an object.
#[derive(Copy, Clone)]
pub enum CreateObjectError {
    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for CreateObjectError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            CreateObjectError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CreateObjectError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CreateObjectError::Session(err)
        }
        else {
            CreateObjectError::Token(TokenError::from(err))
        }
    }
}


//------------ CopyObjectError -----------------------------------------------

/// An error happened when copying an object.
#[derive(Copy, Clone)]
pub enum CopyObjectError {
    /// The specified object handle is not valid.
    ObjectHandleInvalid,

    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for CopyObjectError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            CopyObjectError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CopyObjectError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CopyObjectError::Session(err)
        }
        else {
            match err {
                sys::CKR_OBJECT_HANDLE_INVALID
                    => CopyObjectError::ObjectHandleInvalid,
                _ => CopyObjectError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ ObjectAccessError ---------------------------------------------

/// An error happened while trying to access an object.
#[derive(Copy, Clone)]
pub enum ObjectAccessError {
    /// The specified object handle is not valid.
    ObjectHandleInvalid,

    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for ObjectAccessError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            ObjectAccessError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            ObjectAccessError::Session(err)
        }
        else {
            match err {
                sys::CKR_OBJECT_HANDLE_INVALID
                    => ObjectAccessError::ObjectHandleInvalid,
                _ => ObjectAccessError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ GetAttributeValueError ---------------------------------------

/// An error happened while trying to get attribute values.
#[derive(Clone, Copy)]
pub enum GetAttributeValueError {
    /// At least one of the attributes was considered sensitive.
    AttributeSensitive,

    /// At least one attribute type was not valid for the object refered to.
    AttributeTypeInvalid,

    /// For at least one attribute was the buffer supplied too small.
    BufferTooSmall,

    /// The object handle given was not valid.
    ObjectHandleInvalid,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for GetAttributeValueError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            GetAttributeValueError::Session(err)
        }
        else {
            match err {
                sys::CKR_ATTRIBUTE_SENSITIVE
                    => GetAttributeValueError::AttributeSensitive,
                sys::CKR_ATTRIBUTE_TYPE_INVALID
                    => GetAttributeValueError::AttributeTypeInvalid,
                sys::CKR_BUFFER_TOO_SMALL
                    => GetAttributeValueError::BufferTooSmall,
                sys::CKR_OBJECT_HANDLE_INVALID
                    => GetAttributeValueError::ObjectHandleInvalid,
                _ => GetAttributeValueError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ FindObjectsInitError ------------------------------------------

/// An error happened while initializing a search for objects.
#[derive(Copy, Clone)]
pub enum FindObjectsInitError {
    /// A search operation is already ongoing within this session.
    OperationActive,

    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for FindObjectsInitError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            FindObjectsInitError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            FindObjectsInitError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            FindObjectsInitError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE
                    => FindObjectsInitError::OperationActive,
                _ => FindObjectsInitError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ ContinuationError --------------------------------------------

/// An error happened during searching for objects.
#[derive(Clone, Copy)]
pub enum ContinuationError {
    /// The operation has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for ContinuationError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            ContinuationError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => ContinuationError::OperationNotInitialized,
                _ => ContinuationError::Token(TokenError::from(err))
            }
        }
    }
}


///----------- CryptoInitError -----------------------------------------------

/// An error happened while initializing a crypto operation.
#[derive(Copy, Clone)]
pub enum CryptoInitError {
    /// An exclusive operation is already active on this session. 
    OperationActive,

    Key(KeyError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for CryptoInitError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            CryptoInitError::Key(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            CryptoInitError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CryptoInitError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CryptoInitError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => CryptoInitError::OperationActive,
                _ => CryptoInitError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ PlaintextError ------------------------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy)]
pub enum PlaintextError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for PlaintextError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            PlaintextError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => PlaintextError::BufferTooSmall,
                sys::CKR_DATA_INVALID => PlaintextError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => PlaintextError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => PlaintextError::OperationNotInitialized,
                _ => PlaintextError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ PlaintextUpdateError ------------------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy)]
pub enum PlaintextUpdateError {
    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for PlaintextUpdateError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            PlaintextUpdateError::Session(err)
        }
        else {
            match err {
                sys::CKR_DATA_INVALID => PlaintextUpdateError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => PlaintextUpdateError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => PlaintextUpdateError::OperationNotInitialized,
                _ => PlaintextUpdateError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ CiphertextError -----------------------------------------------

/// An error happened while performing an operation with ciphertext input.
#[derive(Clone, Copy)]
pub enum CiphertextError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// The ciphertext input to a cryptographic operation is invalid.
    EncryptedDataInvalid,

    /// The ciphertext input to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    EncryptedDataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for CiphertextError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            CiphertextError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => CiphertextError::BufferTooSmall,
                sys::CKR_ENCRYPTED_DATA_INVALID
                    => CiphertextError::EncryptedDataInvalid,
                sys::CKR_ENCRYPTED_DATA_LEN_RANGE
                    => CiphertextError::EncryptedDataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => CiphertextError::OperationNotInitialized,
                _ => CiphertextError::Token(TokenError::from(err))
            }
        }
    }
}


///----------- DigestInitError -----------------------------------------------

/// An error happened while initializing a digest operation.
#[derive(Copy, Clone)]
pub enum DigestInitError {
    /// An exclusive operation is already active on this session. 
    OperationActive,

    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DigestInitError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = MechanismError::from_rv(err) {
            DigestInitError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            DigestInitError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            DigestInitError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => DigestInitError::OperationActive,
                _ => DigestInitError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ DigestError ---------------------------------------------------

/// An error happened while performing an operation with ciphertext input.
#[derive(Clone, Copy)]
pub enum DigestError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DigestError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            DigestError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => DigestError::BufferTooSmall,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => DigestError::OperationNotInitialized,
                _ => DigestError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ DigestKeyError ------------------------------------------------

/// An error happened while digesting a key.
#[derive(Copy, Clone)]
pub enum DigestKeyError {
    /// The given key cannot be digested for some reason.
    ///
    /// Perhaps the key isn’t a secret key, or perhaps the token simply can’t
    /// digest this kind of key.
    KeyIndigestible,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Key(KeyError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DigestKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            DigestKeyError::Key(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            DigestKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_KEY_INDIGESTIBLE => DigestKeyError::KeyIndigestible,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => DigestKeyError::OperationNotInitialized,
                _ => DigestKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ VerifyError ------------------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy)]
pub enum VerifyError {
    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    /// The provided signature or MAC is invalid.
    SignatureInvalid,

    /// The provided signature or MAC is invalid because of a wrong length.
    SignatureLenRange,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for VerifyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            VerifyError::Session(err)
        }
        else {
            match err {
                sys::CKR_DATA_INVALID => VerifyError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => VerifyError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => VerifyError::OperationNotInitialized,
                sys::CKR_SIGNATURE_INVALID => VerifyError::SignatureInvalid,
                sys::CKR_SIGNATURE_LEN_RANGE
                    => VerifyError::SignatureLenRange,
                _ => VerifyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ VerifyRecoverError -----------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy)]
pub enum VerifyRecoverError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    /// The provided signature or MAC is invalid.
    SignatureInvalid,

    /// The provided signature or MAC is invalid because of a wrong length.
    SignatureLenRange,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for VerifyRecoverError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            VerifyRecoverError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL
                    => VerifyRecoverError::BufferTooSmall,
                sys::CKR_DATA_INVALID => VerifyRecoverError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => VerifyRecoverError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => VerifyRecoverError::OperationNotInitialized,
                sys::CKR_SIGNATURE_INVALID
                    => VerifyRecoverError::SignatureInvalid,
                sys::CKR_SIGNATURE_LEN_RANGE
                    => VerifyRecoverError::SignatureLenRange,
                _ => VerifyRecoverError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ CreateKeyError ---------------------------------------------

/// An error happened when creating an object.
#[derive(Copy, Clone)]
pub enum CreateKeyError {
    Template(TemplateError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for CreateKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            CreateKeyError::Template(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            CreateKeyError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CreateKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CreateKeyError::Session(err)
        }
        else {
            CreateKeyError::Token(TokenError::from(err))
        }
    }
}


//------------ WrapKeyError --------------------------------------------------

/// An error happened when wrapping a key.
#[derive(Copy, Clone)]
pub enum WrapKeyError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// While the key is allowed to be wrapped, the library just can’t.
    KeyNotWrappable,

    /// The key cannot be wrapped because it isn’t allowed to.
    ///
    /// This happens if the `CKA_EXTRACTABLE` attribute is set to `false`.
    KeyUnextractable,

    /// An operation is currently active and needs to be finished first.
    OperationActive,

    Key(KeyError),
    WrappingKey(KeyError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for WrapKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            WrapKeyError::Key(err)
        }
        else if let Some(err) = KeyError::wrapping_from_rv(err) {
            WrapKeyError::WrappingKey(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            WrapKeyError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            WrapKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            WrapKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => WrapKeyError::BufferTooSmall,
                sys::CKR_KEY_NOT_WRAPPABLE => WrapKeyError::KeyNotWrappable,
                sys::CKR_KEY_UNEXTRACTABLE => WrapKeyError::KeyUnextractable,
                sys::CKR_OPERATION_ACTIVE => WrapKeyError::OperationActive,
                _ => WrapKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ UnwrapKeyError ------------------------------------------------

/// An error happened when wrapping a key.
#[derive(Copy, Clone)]
pub enum UnwrapKeyError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// An operation is currently active and needs to be finished first.
    OperationActive,

    /// The wrapped key is invalid.
    WrappedKeyInvalid,

    /// The wrapped key can’t be valid because of its size.
    WrappedKeyLenRange,

    UnwrappingKey(KeyError),
    Mechanism(MechanismError),
    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for UnwrapKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::unwrapping_from_rv(err) {
            UnwrapKeyError::UnwrappingKey(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            UnwrapKeyError::Mechanism(err)
        }
        else if let Some(err) = TemplateError::from_rv(err) {
            UnwrapKeyError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            UnwrapKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            UnwrapKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => UnwrapKeyError::BufferTooSmall,
                sys::CKR_OPERATION_ACTIVE => UnwrapKeyError::OperationActive,
                sys::CKR_WRAPPED_KEY_INVALID
                    => UnwrapKeyError::WrappedKeyInvalid,
                sys::CKR_WRAPPED_KEY_LEN_RANGE
                    => UnwrapKeyError::WrappedKeyLenRange,
                _ => UnwrapKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ DeriveKeyError ------------------------------------------------

/// An error occurred while deriving a key.
#[derive(Copy, Clone)]
pub enum DeriveKeyError {
    /// An operation is currently active and needs to be finished first.
    OperationActive,

    Key(KeyError),
    Template(TemplateError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DeriveKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            DeriveKeyError::Key(err)
        }
        else if let Some(err) = TemplateError::from_rv(err) {
            DeriveKeyError::Template(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            DeriveKeyError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            DeriveKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            DeriveKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => DeriveKeyError::OperationActive,
                _ => DeriveKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ SeedRandomError -----------------------------------------------

/// An error happened while seeding the token’s random number generator.
#[derive(Clone, Copy)]
pub enum SeedRandomError {
    OperationActive,
    RandomSeedNotSupported,
    RandomNoRng,
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for SeedRandomError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            SeedRandomError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            SeedRandomError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => SeedRandomError::OperationActive,
                sys::CKR_RANDOM_SEED_NOT_SUPPORTED
                    => SeedRandomError::RandomSeedNotSupported,
                sys::CKR_RANDOM_NO_RNG => SeedRandomError::RandomNoRng,
                _ => SeedRandomError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ GenerateRandomError -------------------------------------------

/// An error happened while generating random data.
#[derive(Clone, Copy)]
pub enum GenerateRandomError {
    OperationActive,
    RandomNoRng,
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for GenerateRandomError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            GenerateRandomError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            GenerateRandomError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE
                    => GenerateRandomError::OperationActive,
                sys::CKR_RANDOM_NO_RNG => GenerateRandomError::RandomNoRng,
                _ => GenerateRandomError::Token(TokenError::from(err))
            }
        }
    }
}

