use std::env;
#[cfg(any(feature = "native-hsmauth", feature = "platform-credential"))]
use std::sync::Arc;
use yubihsm_qualification::Credentials;

pub fn connector_credentials(authentication_key_id: u16) -> Result<Credentials, String> {
    if let Ok(label) = env::var("YUBIHSM_QUALIFICATION_HSMAUTH_LABEL") {
        #[cfg(feature = "native-hsmauth")]
        {
            let password = env::var("YUBIHSM_QUALIFICATION_HSMAUTH_PASSWORD").map_err(|_| {
                "YUBIHSM Auth qualification requires YUBIHSM_QUALIFICATION_HSMAUTH_PASSWORD"
                    .to_owned()
            })?;
            let reader = env::var("YUBIHSM_QUALIFICATION_HSMAUTH_READER").ok();
            return Ok(Credentials::from_asymmetric(
                authentication_key_id,
                Arc::new(hsmauth::Provider::new(label, password.into_bytes(), reader)),
            ));
        }
        #[cfg(not(feature = "native-hsmauth"))]
        {
            let _ = label;
            return Err(
                "YubiHSM Auth qualification requires the native-hsmauth feature".to_owned(),
            );
        }
    }

    if let Ok(name) = env::var("YUBIHSM_QUALIFICATION_PLATFORM_CREDENTIAL") {
        #[cfg(feature = "platform-credential")]
        {
            return Ok(Credentials::from_asymmetric(
                authentication_key_id,
                Arc::new(platform::Provider::resolve(name)?),
            ));
        }
        #[cfg(not(feature = "platform-credential"))]
        {
            let _ = name;
            return Err(
                "platform qualification requires the platform-credential feature".to_owned(),
            );
        }
    }

    let password = env::var("YUBIHSM_QUALIFICATION_PASSWORD").map_err(|_| {
        "authenticated qualification requires a YubiHSM Auth, platform, or direct symmetric credential"
            .to_owned()
    })?;
    Ok(Credentials::from_password(
        authentication_key_id,
        password.as_bytes(),
    ))
}

#[cfg(feature = "platform-credential")]
mod platform {
    use getrandom::fill;
    use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
    use platform_credential::{
        PlatformAuthenticationCredential, PrefixedX963Credential, resolve_platform_credential,
    };
    use software_key_core::{
        digest::HashAlgorithm,
        software_signing::{EcCurve, SoftwarePublicKey},
    };
    use std::sync::Arc;
    use yubihsm_qualification::{
        AsymmetricCredentialAttempt, AsymmetricCredentialProvider, AsymmetricSessionKeys,
        CaseResult,
    };
    use zeroize::{Zeroize, Zeroizing};

    pub struct Provider {
        name: String,
        credential: Arc<dyn PrefixedX963Credential>,
    }

    impl Provider {
        pub fn resolve(name: String) -> Result<Self, String> {
            match resolve_platform_credential(&name).map_err(|error| error.to_string())? {
                PlatformAuthenticationCredential::Asymmetric(credential) => {
                    Ok(Self { name, credential })
                }
                PlatformAuthenticationCredential::Symmetric(_) => Err(format!(
                    "platform credential {name:?} is symmetric; asymmetric YubiHSM authentication requires P-256"
                )),
            }
        }
    }

    impl AsymmetricCredentialProvider for Provider {
        fn begin(&self) -> CaseResult<Box<dyn AsymmetricCredentialAttempt>> {
            let secret = loop {
                let mut scalar = Zeroizing::new([0; 32]);
                fill(scalar.as_mut())
                    .map_err(|error| format!("random generation failed: {error}"))?;
                if let Ok(secret) = p256::SecretKey::from_slice(scalar.as_ref()) {
                    break secret;
                }
                scalar.zeroize();
            };
            let host_public_key = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
            Ok(Box::new(Attempt {
                credential: self.credential.clone(),
                secret,
                host_public_key,
            }))
        }

        fn description(&self) -> String {
            format!("platform credential {:?}", self.name)
        }
    }

    struct Attempt {
        credential: Arc<dyn PrefixedX963Credential>,
        secret: p256::SecretKey,
        host_public_key: Vec<u8>,
    }

    impl AsymmetricCredentialAttempt for Attempt {
        fn host_public_key(&self) -> &[u8] {
            &self.host_public_key
        }

        fn derive_session_keys(
            &mut self,
            context: &[u8],
            device_public_key: &[u8],
            _receipt: &[u8],
        ) -> CaseResult<AsymmetricSessionKeys> {
            if context.len() != 130 || context[..65] != self.host_public_key {
                return Err("asymmetric session context changed the host public key".to_owned());
            }
            let device_ephemeral = p256::PublicKey::from_sec1_bytes(&context[65..])
                .map_err(|error| format!("invalid device ephemeral key: {error}"))?;
            let ephemeral_secret = diffie_hellman(
                self.secret.to_nonzero_scalar(),
                device_ephemeral.as_affine(),
            );
            let peer = SoftwarePublicKey::Ec {
                curve: EcCurve::P256,
                uncompressed: device_public_key.to_vec(),
            };
            let keys = self
                .credential
                .derive_prefixed_x963(
                    &peer,
                    HashAlgorithm::Sha256,
                    ephemeral_secret.raw_secret_bytes(),
                    &[0x3c, 0x88, 0x10],
                    64,
                )
                .map_err(|error| format!("platform session-key derivation failed: {error}"))?;
            split_session_keys(&keys)
        }
    }

    fn split_session_keys(keys: &[u8]) -> CaseResult<AsymmetricSessionKeys> {
        if keys.len() != 64 {
            return Err(format!(
                "session KDF returned {} bytes, expected 64",
                keys.len()
            ));
        }
        Ok(AsymmetricSessionKeys {
            receipt: Some(Zeroizing::new(keys[..16].try_into().unwrap())),
            encryption: Zeroizing::new(keys[16..32].try_into().unwrap()),
            mac: Zeroizing::new(keys[32..48].try_into().unwrap()),
            response_mac: Zeroizing::new(keys[48..64].try_into().unwrap()),
        })
    }
}

#[cfg(feature = "native-hsmauth")]
mod hsmauth {
    use pcsc::{Card, Context, Protocols, Scope, ShareMode};
    use std::{
        error::Error,
        ffi::CString,
        fmt,
        sync::{Arc, Mutex},
    };
    use yubihsm_auth_client::{Client, Command, Response, Transport};
    use yubihsm_qualification::{
        AsymmetricCredentialAttempt, AsymmetricCredentialProvider, AsymmetricSessionKeys,
        CaseResult,
    };
    use zeroize::Zeroizing;

    pub struct Provider {
        label: String,
        password: Zeroizing<Vec<u8>>,
        reader_filter: Option<String>,
    }

    impl Provider {
        pub fn new(label: String, password: Vec<u8>, reader_filter: Option<String>) -> Self {
            Self {
                label,
                password: Zeroizing::new(password),
                reader_filter,
            }
        }
    }

    impl AsymmetricCredentialProvider for Provider {
        fn begin(&self) -> CaseResult<Box<dyn AsymmetricCredentialAttempt>> {
            let context = Context::establish(Scope::System)
                .map_err(|error| format!("PC/SC initialization failed: {error}"))?;
            let readers = context
                .list_readers_owned()
                .map_err(|error| format!("PC/SC reader enumeration failed: {error}"))?;
            let mut selected = None;
            for reader in readers {
                let name = reader.to_string_lossy().into_owned();
                if self
                    .reader_filter
                    .as_ref()
                    .is_some_and(|filter| !name.contains(filter))
                {
                    continue;
                }
                let card = match context.connect(
                    &reader,
                    ShareMode::Shared,
                    Protocols::T0 | Protocols::T1,
                ) {
                    Ok(card) => card,
                    Err(_) => continue,
                };
                let transport = Arc::new(PcscTransport {
                    card: Mutex::new(card),
                    reader: reader.clone(),
                });
                if Client.select(transport.as_ref()).is_err() {
                    continue;
                }
                let challenge = match Client.get_challenge(
                    transport.as_ref(),
                    &self.label,
                    Some(self.password.as_ref()),
                ) {
                    Ok(challenge) => challenge,
                    Err(_) => continue,
                };
                if challenge.len() != 65 || challenge[0] != 0x04 {
                    continue;
                }
                if selected.is_some() {
                    return Err(format!(
                        "YubiHSM Auth credential {:?} is available on more than one reader; set YUBIHSM_QUALIFICATION_HSMAUTH_READER",
                        self.label
                    ));
                }
                selected = Some(Attempt {
                    transport,
                    label: self.label.clone(),
                    password: self.password.clone(),
                    host_public_key: challenge,
                });
            }
            selected
                .map(|attempt| Box::new(attempt) as Box<dyn AsymmetricCredentialAttempt>)
                .ok_or_else(|| {
                    format!(
                        "YubiHSM Auth credential {:?} was not available on a matching PC/SC reader",
                        self.label
                    )
                })
        }

        fn description(&self) -> String {
            format!("YubiHSM Auth credential {:?}", self.label)
        }
    }

    struct Attempt {
        transport: Arc<PcscTransport>,
        label: String,
        password: Zeroizing<Vec<u8>>,
        host_public_key: Vec<u8>,
    }

    impl AsymmetricCredentialAttempt for Attempt {
        fn host_public_key(&self) -> &[u8] {
            &self.host_public_key
        }

        fn derive_session_keys(
            &mut self,
            context: &[u8],
            device_public_key: &[u8],
            receipt: &[u8],
        ) -> CaseResult<AsymmetricSessionKeys> {
            let keys = Client
                .calculate_session_keys_asymmetric(
                    self.transport.as_ref(),
                    &self.label,
                    context,
                    device_public_key,
                    receipt,
                    self.password.as_ref(),
                )
                .map_err(|error| format!("YubiHSM Auth calculation failed: {error}"))?;
            Ok(AsymmetricSessionKeys {
                receipt: None,
                encryption: keys.enc,
                mac: keys.mac,
                response_mac: keys.rmac,
            })
        }
    }

    struct PcscTransport {
        card: Mutex<Card>,
        reader: CString,
    }

    #[derive(Debug)]
    enum PcscTransportError {
        Pcsc(pcsc::Error),
        Poisoned,
        MalformedResponse,
        ChainingResponse,
    }

    impl fmt::Display for PcscTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Pcsc(error) => write!(formatter, "{error}"),
                Self::Poisoned => formatter.write_str("PC/SC card lock is poisoned"),
                Self::MalformedResponse => formatter.write_str("PC/SC response has no status word"),
                Self::ChainingResponse => {
                    formatter.write_str("invalid intermediate APDU chaining response")
                }
            }
        }
    }

    impl Error for PcscTransportError {}

    impl Transport for PcscTransport {
        type Error = PcscTransportError;

        fn exchange(&self, command: &Command) -> Result<Response, Self::Error> {
            let card = self.card.lock().map_err(|_| PcscTransportError::Poisoned)?;
            let mut chunks = command.data.chunks(255).peekable();
            if command.data.is_empty() {
                return transmit(
                    &card,
                    command.cla,
                    command.instruction,
                    command.p1,
                    command.p2,
                    &[],
                );
            }
            while let Some(chunk) = chunks.next() {
                let last = chunks.peek().is_none();
                let response = transmit(
                    &card,
                    if last {
                        command.cla
                    } else {
                        command.cla | 0x10
                    },
                    command.instruction,
                    command.p1,
                    command.p2,
                    chunk,
                )?;
                if last {
                    return Ok(response);
                }
                if response.status != 0x9000 || !response.data.is_empty() {
                    return Err(PcscTransportError::ChainingResponse);
                }
            }
            unreachable!("non-empty APDU has at least one chunk")
        }
    }

    impl fmt::Debug for PcscTransport {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("PcscTransport")
                .field("reader", &self.reader)
                .finish_non_exhaustive()
        }
    }

    fn transmit(
        card: &Card,
        cla: u8,
        instruction: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Response, PcscTransportError> {
        let mut encoded = Zeroizing::new(Vec::with_capacity(data.len() + 5));
        encoded.extend_from_slice(&[cla, instruction, p1, p2, data.len() as u8]);
        encoded.extend_from_slice(data);
        let mut response = vec![0; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let received = card
            .transmit(&encoded, &mut response)
            .map_err(PcscTransportError::Pcsc)?;
        let length = received.len();
        response.truncate(length);
        if response.len() < 2 {
            return Err(PcscTransportError::MalformedResponse);
        }
        let status =
            u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]]);
        response.truncate(response.len() - 2);
        Ok(Response {
            data: response,
            status,
        })
    }
}
