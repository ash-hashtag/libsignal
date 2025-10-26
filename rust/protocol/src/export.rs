#![allow(unused)]

use std::error::Error;
use std::fmt;
use std::panic::UnwindSafe;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use js_sys::{Date, Function, Promise, Uint8Array};
use rand::SeedableRng;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::kem::{self, KeyPair as CoreKemKeyPair, PublicKey as CoreKemPublicKey};
use crate::proto::storage::SignedPreKeyRecordStructure;
use crate::{
    CiphertextMessage, CiphertextMessageType, DeviceId, Direction, GenericSignedPreKey,
    IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KeyPair as CoreKeyPair,
    KyberPreKeyId, KyberPreKeyRecord as CoreKyberPreKeyRecord, KyberPreKeyStore,
    PreKeyBundle as CorePreKeyBundle, PreKeyId, PreKeyRecord as CorePreKeyRecord,
    PreKeySignalMessage as CorePreKeySignalMessage, PreKeyStore, PrivateKey as CorePrivateKey,
    ProtocolAddress as CoreProtocolAddress, PublicKey as CorePublicKey, SessionRecord,
    SessionStore, SignalMessage as CoreSignalMessage, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord as CoreSignedPreKeyRecord, SignedPreKeyStore, Timestamp, message_decrypt,
    message_decrypt_prekey, message_encrypt, process_prekey_bundle,
};




#[derive(Debug)]
struct StrErr(String);
impl fmt::Display for StrErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for StrErr {}

// ========================================
// ProtocolAddress
// ========================================
#[wasm_bindgen]
pub struct ProtocolAddress {
    inner: CoreProtocolAddress,
}

#[wasm_bindgen]
impl ProtocolAddress {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, device_id: u8) -> Result<ProtocolAddress, JsError> {
        Ok(Self {
            inner: CoreProtocolAddress::new(name, DeviceId::new(device_id)?),
        })
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> u8 {
        self.inner.device_id().into()
    }

    pub fn name(&self) -> String {
        self.inner.name().to_owned()
    }
}

// ========================================
// PrivateKey
// ========================================
#[wasm_bindgen]
pub struct PrivateKey {
    inner: CorePrivateKey,
}

#[wasm_bindgen]
pub struct KeyPair {
    inner: CoreKeyPair,
}

#[wasm_bindgen]
impl KeyPair {
    pub fn generate() -> Self {
        let inner = CoreKeyPair::generate(&mut rand::rng());

        Self { inner }
    }
}

#[wasm_bindgen]
impl PrivateKey {
    pub fn generate() -> Self {
        let pair = KeyPair::generate();
        Self {
            inner: pair.inner.private_key,
        }
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: self.inner.public_key()?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    pub fn deserialize(data: &[u8]) -> Result<PrivateKey, JsError> {
        Ok(Self {
            inner: CorePrivateKey::deserialize(data)?,
        })
    }
}

// ========================================
// PublicKey
// ========================================
#[wasm_bindgen]
pub struct PublicKey {
    inner: CorePublicKey,
}

#[wasm_bindgen]
impl PublicKey {
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    pub fn deserialize(data: &[u8]) -> Result<PublicKey, JsError> {
        Ok(Self {
            inner: CorePublicKey::deserialize(data)?,
        })
    }
}

// ========================================
// IdentityKeyPair
// ========================================
#[wasm_bindgen]
pub struct IdentityKeyPairWrapper {
    inner: IdentityKeyPair,
}

#[wasm_bindgen]
impl IdentityKeyPairWrapper {
    pub fn generate() -> Self {
        Self {
            inner: IdentityKeyPair::generate(&mut rand::rng()),
        }
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> PublicKey {
        PublicKey {
            inner: *self.inner.public_key(),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self
            .inner
            .private_key()
            .calculate_signature(data, &mut rand::rng())?
            .to_vec())
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    pub fn deserialize(data: &[u8]) -> Result<IdentityKeyPairWrapper, JsError> {
        Ok(Self {
            inner: IdentityKeyPair::try_from(data)?,
        })
    }
}

// ========================================
// KEMKeyPair
// ========================================
#[wasm_bindgen]
pub struct KEMKeyPair {
    inner: CoreKemKeyPair,
}

#[wasm_bindgen]
impl KEMKeyPair {
    pub fn generate() -> Self {
        Self {
            inner: CoreKemKeyPair::generate(kem::KeyType::Kyber1024, &mut rand::rng()),
        }
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> KEMPublicKey {
        KEMPublicKey {
            inner: self.inner.public_key.clone(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.secret_key.serialize().to_vec()
    }
}

// ========================================
// KEMPublicKey
// ========================================
#[wasm_bindgen]
pub struct KEMPublicKey {
    inner: CoreKemPublicKey,
}

#[wasm_bindgen]
impl KEMPublicKey {
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    pub fn deserialize(data: &[u8]) -> Result<KEMPublicKey, JsError> {
        Ok(Self {
            inner: CoreKemPublicKey::deserialize(data)?,
        })
    }
}

// ========================================
// PreKeyRecord
// ========================================
#[wasm_bindgen]
pub struct PreKeyRecord {
    inner: CorePreKeyRecord,
}

#[wasm_bindgen]
impl PreKeyRecord {
    #[wasm_bindgen(constructor)]
    pub fn new(id: u32, public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            inner: CorePreKeyRecord::new(
                id.into(),
                &CoreKeyPair::new(public_key.inner, private_key.inner),
            ),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.serialize()?)
    }

    pub fn deserialize(data: &[u8]) -> Result<PreKeyRecord, JsError> {
        Ok(Self {
            inner: CorePreKeyRecord::deserialize(data)?,
        })
    }
}

// ========================================
// SignedPreKeyRecord
// ========================================
#[wasm_bindgen]
pub struct SignedPreKeyRecord {
    inner: CoreSignedPreKeyRecord,
}

#[wasm_bindgen]
impl SignedPreKeyRecord {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: u32,
        timestamp: u64,
        public_key: PublicKey,
        private_key: PrivateKey,
        signature: &[u8],
    ) -> Self {
        Self {
            inner: CoreSignedPreKeyRecord::new(
                id.into(),
                Timestamp::from_epoch_millis(timestamp),
                &CoreKeyPair::new(public_key.inner, private_key.inner),
                signature,
            ),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.serialize()?)
    }

    pub fn deserialize(data: &[u8]) -> Result<SignedPreKeyRecord, JsError> {
        Ok(Self {
            inner: CoreSignedPreKeyRecord::deserialize(data)?,
        })
    }
}

// ========================================
// KyberPreKeyRecord
// ========================================
#[wasm_bindgen]
pub struct KyberPreKeyRecord {
    inner: CoreKyberPreKeyRecord,
}

#[wasm_bindgen]
impl KyberPreKeyRecord {
    #[wasm_bindgen(constructor)]
    pub fn new(id: u32, timestamp: u64, key_pair: &KEMKeyPair, signature: &[u8]) -> Self {
        Self {
            inner: CoreKyberPreKeyRecord::new(
                id.into(),
                Timestamp::from_epoch_millis(timestamp),
                &key_pair.inner,
                signature,
            ),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.serialize()?)
    }

    pub fn deserialize(data: &[u8]) -> Result<KyberPreKeyRecord, JsError> {
        Ok(Self {
            inner: CoreKyberPreKeyRecord::deserialize(data)?,
        })
    }
}

// ========================================
// PreKeyBundle
// ========================================
#[wasm_bindgen]
pub struct PreKeyBundle {
    inner: CorePreKeyBundle,
}

#[wasm_bindgen]
impl PreKeyBundle {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: u32,
        device_id: u8,
        pre_key_id: u32,
        pre_key_public: &PublicKey,
        signed_pre_key_id: u32,
        signed_pre_key_public: &PublicKey,
        signed_pre_key_signature: &[u8],
        identity_key: &PublicKey,
        kyber_pre_key_id: u32,
        kyber_pre_key_public: &KEMPublicKey,
        kyber_pre_key_signature: &[u8],
    ) -> Result<PreKeyBundle, JsError> {
        Ok(Self {
            inner: CorePreKeyBundle::new(
                registration_id,
                DeviceId::new(device_id)?,
                Some((pre_key_id.into(), pre_key_public.inner)),
                signed_pre_key_id.into(),
                signed_pre_key_public.inner.clone(),
                signed_pre_key_signature.to_vec(),
                kyber_pre_key_id.into(),
                kyber_pre_key_public.inner.clone(),
                kyber_pre_key_signature.to_vec(),
                IdentityKey::new(identity_key.inner),
            )?,
        })
    }
}

// ========================================
// PreKeySignalMessage
// ========================================
#[wasm_bindgen]
pub struct PreKeySignalMessage {
    inner: CorePreKeySignalMessage,
}

#[wasm_bindgen]
impl PreKeySignalMessage {
    pub fn deserialize(data: &[u8]) -> Result<PreKeySignalMessage, JsError> {
        Ok(Self {
            inner: CorePreKeySignalMessage::try_from(data)?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialized().to_vec()
    }
}

// ========================================
// SignalMessage
// ========================================
#[wasm_bindgen]
pub struct SignalMessage {
    inner: CoreSignalMessage,
}

#[wasm_bindgen]
impl SignalMessage {
    pub fn deserialize(data: &[u8]) -> Result<SignalMessage, JsError> {
        Ok(Self {
            inner: CoreSignalMessage::try_from(data)?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialized().to_vec()
    }
}

// ========================================
// CiphertextMessage
// ========================================
#[wasm_bindgen]
pub struct CiphertextMessageWrapper {
    inner: CiphertextMessage,
}

#[wasm_bindgen]
impl CiphertextMessageWrapper {
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    #[wasm_bindgen(js_name = type)]
    pub fn message_type(&self) -> u8 {
        match self.inner.message_type() {
            CiphertextMessageType::Whisper => 2,
            CiphertextMessageType::PreKey => 3,
            CiphertextMessageType::SenderKey => 7,
            CiphertextMessageType::Plaintext => 8,
        }
    }
}
// ========================================
// UsePQRatchet enum
// ========================================
#[wasm_bindgen]
pub enum UsePQRatchet {
    Yes,
    No,
}

impl From<UsePQRatchet> for bool {
    fn from(val: UsePQRatchet) -> Self {
        matches!(val, UsePQRatchet::Yes)
    }
}

#[wasm_bindgen]
pub struct JsSessionStore {
    load_session_handler: Function,
    store_session_handler: Function,
}

#[wasm_bindgen]
impl JsSessionStore {
    #[wasm_bindgen(constructor)]
    pub fn new(load_session_handler: Function, store_session_handler: Function) -> Self {
        Self {
            load_session_handler,
            store_session_handler,
        }
    }
}

#[async_trait(?Send)]
impl SessionStore for JsSessionStore {
    #[doc = " Look up the session corresponding to `address`."]
    #[must_use]
    #[allow(
        elided_named_lifetimes,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds
    )]
    async fn load_session(
        &self,
        address: &CoreProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let arg = address.to_string();
        let value = match self
            .load_session_handler
            .call1(&JsValue::NULL, &JsValue::from(arg))
        {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }

        let arr = Uint8Array::from(value);
        let bytes = arr.to_vec();

        let record = SessionRecord::deserialize(&bytes)?;

        Ok(Some(record))
    }

    #[doc = " Set the entry for `address` to the value of `record`."]
    #[must_use]
    #[allow(
        elided_named_lifetimes,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds
    )]
    async fn store_session(
        &mut self,
        address: &CoreProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let arg1 = address.to_string();
        let arg2 = record.serialize()?;

        let value = match self.store_session_handler.call2(
            &JsValue::NULL,
            &JsValue::from(arg1),
            &JsValue::from(arg2),
        ) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };
        _ = value;

        Ok(())
    }
}

#[wasm_bindgen]
pub struct JsIdentityKeyStore {
    is_trusted_identity_handler: Function,
    get_identity_key_pair_handler: Function,
    get_local_registration_id_handler: Function,
    save_identity_handler: Function,
    get_identity_handler: Function,
}

#[wasm_bindgen]
impl JsIdentityKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new(
        is_trusted_identity_handler: Function,
        get_identity_key_pair_handler: Function,
        get_local_registration_id_handler: Function,
        save_identity_handler: Function,
        get_identity_handler: Function,
    ) -> Self {
        Self {
            is_trusted_identity_handler,
            get_identity_key_pair_handler,
            get_local_registration_id_handler,
            save_identity_handler,
            get_identity_handler,
        }
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for JsIdentityKeyStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let value = match self.get_identity_key_pair_handler.call0(&JsValue::NULL) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };


        let arr = Uint8Array::from(value);
        let bytes = arr.to_vec();
        let pair = IdentityKeyPair::try_from(bytes.as_slice())?;
        Ok(pair)
    }

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// may be the same, but the store registration id returned by this method should
    /// be regenerated.
    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let value = match self.get_local_registration_id_handler.call0(&JsValue::NULL) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        Ok(value.as_f64().unwrap_or(1f64) as u32)
    }

    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced.
    async fn save_identity(
        &mut self,
        address: &CoreProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let arg1 = address.to_string();
        let arg2 = identity.serialize();
        let value = match self.save_identity_handler.call2(
            &JsValue::NULL,
            &JsValue::from(arg1),
            &JsValue::from(arg2),
        ) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };


        Ok(if value.as_bool().unwrap_or_default() {
            IdentityChange::NewOrUnchanged
        } else {
            IdentityChange::ReplacedExisting
        })
    }

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &CoreProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let arg1 = address.to_string();
        let arg2 = identity.serialize();
        let arg3 = direction;
        let value = match self.is_trusted_identity_handler.call3(
            &JsValue::NULL,
            &JsValue::from(arg1),
            &JsValue::from(arg2),
            &JsValue::from(arg3),
        ) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };


        Ok(value.as_bool().unwrap_or_default())
    }

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(
        &self,
        address: &CoreProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let arg = address.to_string();
        let value = match self
            .get_identity_handler
            .call1(&JsValue::NULL, &JsValue::from(arg))
        {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }

        let arr = Uint8Array::from(value);
        let bytes = arr.to_vec();

        Ok(Some(IdentityKey::decode(bytes.as_slice())?))
    }
}

#[wasm_bindgen]
pub struct JsPreKeyStore {
    get_pre_key_handler: Function,
    save_pre_key_handler: Function,
    remove_pre_key_handler: Function,
}

#[wasm_bindgen]

impl JsPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new(
        get_pre_key_handler: Function,
        save_pre_key_handler: Function,
        remove_pre_key_handler: Function,
    ) -> Self {
        Self {
            get_pre_key_handler,
            save_pre_key_handler,
            remove_pre_key_handler,
        }
    }
}

#[async_trait(?Send)]
impl PreKeyStore for JsPreKeyStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
    ) -> Result<CorePreKeyRecord, SignalProtocolError> {
        let arg = prekey_id.to_string();
        let value = match self
            .get_pre_key_handler
            .call1(&JsValue::NULL, &JsValue::from(arg))
        {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let arr = Uint8Array::from(value);
        let bytes = arr.to_vec();

        Ok(CorePreKeyRecord::deserialize(bytes.as_slice())?)
    }

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &CorePreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let arg1 = prekey_id.to_string();
        let arg2 = record.serialize()?;

        let value = match self.save_pre_key_handler.call2(
            &JsValue::NULL,
            &JsValue::from(arg1),
            &JsValue::from(arg2),
        ) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };


        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        _ = value;

        Ok(())
    }

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let arg = prekey_id.to_string();
        let value = match self
            .remove_pre_key_handler
            .call1(&JsValue::NULL, &JsValue::from(arg))
        {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };
        _ = value;

        Ok(())
    }
}

#[wasm_bindgen]
pub struct JsSignedPreKeyStore {
    get_signed_pre_key_handler: Function,
    save_signed_pre_key_handler: Function,
}

#[wasm_bindgen]

impl JsSignedPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new(
        get_signed_pre_key_handler: Function,
        save_signed_pre_key_handler: Function,
    ) -> Self {
        Self {
            get_signed_pre_key_handler,
            save_signed_pre_key_handler,
        }
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for JsSignedPreKeyStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<CoreSignedPreKeyRecord, SignalProtocolError> {
        let arg = signed_prekey_id.to_string();
        let value = match self
            .get_signed_pre_key_handler
            .call1(&JsValue::NULL, &JsValue::from(arg))
        {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let arr = Uint8Array::from(value);
        let bytes = arr.to_vec();

        Ok(CoreSignedPreKeyRecord::deserialize(bytes.as_slice())?)
    }

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &CoreSignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let arg1 = signed_prekey_id.to_string();
        let arg2 = record.serialize()?;

        let value = match self.save_signed_pre_key_handler.call2(
            &JsValue::NULL,
            &JsValue::from(arg1),
            &JsValue::from(arg2),
        ) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        _ = value;
        Ok(())
    }
}

#[wasm_bindgen]
pub struct JsKyberPreKeyStore {
    get_kyber_pre_key_handler: Function,
    save_kyber_pre_key_handler: Function,
    mark_kyber_pre_key_used_handler: Function,
}

#[wasm_bindgen]
impl JsKyberPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new(
        get_kyber_pre_key_handler: Function,
        save_kyber_pre_key_handler: Function,
        mark_kyber_pre_key_used_handler: Function,
    ) -> Self {
        Self {
            get_kyber_pre_key_handler,
            save_kyber_pre_key_handler,
            mark_kyber_pre_key_used_handler,
        }
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for JsKyberPreKeyStore {
    /// Look up the signed kyber pre-key corresponding to `kyber_prekey_id`.
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<CoreKyberPreKeyRecord, SignalProtocolError> {
        let arg = kyber_prekey_id.to_string();
        let value = match self
            .get_kyber_pre_key_handler
            .call1(&JsValue::NULL, &JsValue::from(arg))
        {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let arr = Uint8Array::from(value);
        let bytes = arr.to_vec();

        Ok(CoreKyberPreKeyRecord::deserialize(bytes.as_slice())?)
    }

    /// Set the entry for `kyber_prekey_id` to the value of `record`.
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &CoreKyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let arg1 = kyber_prekey_id.to_string();
        let arg2 = record.serialize()?;

        let value = match self.save_kyber_pre_key_handler.call2(
            &JsValue::NULL,
            &JsValue::from(arg1),
            &JsValue::from(arg2),
        ) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        _ = value;
        Ok(())
    }

    /// Mark the entry for `kyber_prekey_id` as "used".
    ///
    /// A one-time Kyber pre-key should be deleted after this point. A last-resort pre-key should
    /// not immediately be deleted, but should check whether the same combination of pre-keys was
    /// used with the given base key before, and produce an error if so.
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &CorePublicKey,
    ) -> Result<(), SignalProtocolError> {
        let arg1 = kyber_prekey_id.to_string();
        let arg2 = ec_prekey_id.to_string();
        let arg3 = base_key.serialize();

        let value = match self.mark_kyber_pre_key_used_handler.call3(
            &JsValue::NULL,
            &JsValue::from(arg1),
            &JsValue::from(arg2),
            &JsValue::from(arg3),
        ) {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        let promise = Promise::from(value);
        let fut = JsFuture::from(promise);

        let value = match fut.await {
            Ok(value) => value,
            Err(err) => {
                return Err(SignalProtocolError::ApplicationCallbackError(
                    "js",
                    Box::new(StrErr(format!("{:?}", err))),
                ));
            }
        };

        _ = value;
        Ok(())
    }
}

// ========================================
// Store Interfaces (extern types)
// ========================================
// ========================================
// Main Protocol Functions
// ========================================

#[wasm_bindgen(js_name = signalEncrypt)]
pub async fn signal_encrypt(
    plaintext: Vec<u8>,
    address: &ProtocolAddress,
    session_store: &mut JsSessionStore,
    identity_store: &mut JsIdentityKeyStore,
    now_ms: u64,
) -> Result<CiphertextMessageWrapper, JsError> {
    let message = crate::message_encrypt(
        &plaintext,
        &address.inner,
        session_store,
        identity_store,
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(now_ms))
            .unwrap(),
        &mut rand::rng(),
    )
    .await?;

    Ok(CiphertextMessageWrapper { inner: message })
}

#[wasm_bindgen(js_name = signalDecrypt)]
pub async fn signal_decrypt(
    ciphertext: &SignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut JsSessionStore,
    identity_store:&mut  JsIdentityKeyStore,
) -> Result<Vec<u8>, JsError> {
    let message = crate::message_decrypt_signal(
        &ciphertext.inner,
        &remote_address.inner,
        session_store,
        identity_store,
        &mut rand::rng(),
    )
    .await?;
    Ok(message)
}

#[wasm_bindgen(js_name = signalDecryptPreKey)]
pub async fn signal_decrypt_pre_key(
    ciphertext: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
     session_store:&mut JsSessionStore,
     identity_store:&mut JsIdentityKeyStore,
     pre_key_store:&mut JsPreKeyStore,
     signed_pre_key_store:&mut JsSignedPreKeyStore,
     kyber_pre_key_store:&mut JsKyberPreKeyStore,
    use_pq_ratchet: UsePQRatchet,
) -> Result<Vec<u8>, JsError> {
    Ok(crate::message_decrypt_prekey(
        &ciphertext.inner,
        &remote_address.inner,
        session_store,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        kyber_pre_key_store,
        &mut rand::rng(),
    )
    .await?)
}

#[wasm_bindgen(js_name = processPreKeyBundle)]
pub async fn process_pre_key_bundle(
    bundle: &PreKeyBundle,
    address: &ProtocolAddress,
    session_store: &mut JsSessionStore,
    identity_store: &mut JsIdentityKeyStore,
    use_pq_ratchet: UsePQRatchet,
    now_ms: u64,
) -> Result<(), JsError> {
    crate::process_prekey_bundle(
        &address.inner,
        session_store,
        identity_store,
        &bundle.inner,
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(now_ms))
            .unwrap(),
        &mut rand::rng(),
    )
    .await?;
    Ok(())
}
