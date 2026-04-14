// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{GroupContext, GroupEpoch, GroupId},
    prelude::{Capabilities, Ciphersuite, Extension, ExtensionType, Extensions, UnknownExtension},
};
use tap::Pipe;
use tls_codec::{Deserialize as _, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{ApqCiphersuite, ApqGroupId, ApqMlsGroup};

pub const APQMLS_EXTENSION_ID: u16 = 0xFF01;
pub const APQMLS_EXTENSION_TYPE: ExtensionType = ExtensionType::Unknown(APQMLS_EXTENSION_ID);

/// The mode of an [`ApqMlsGroup`], which determines whether only confidentiality or both
/// confidentiality and authentication is PQ secure.
#[derive(Default, Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PqtMode {
    #[default]
    ConfOnly,
    ConfAndAuth,
}

impl From<PqtMode> for bool {
    fn from(value: PqtMode) -> Self {
        match value {
            PqtMode::ConfOnly => false,
            PqtMode::ConfAndAuth => true,
        }
    }
}

impl PqtMode {
    /// Returns the default ciphersuite for the given mode.
    pub fn default_ciphersuite(&self) -> ApqCiphersuite {
        match self {
            PqtMode::ConfOnly => ApqCiphersuite::default_pq_conf(),
            PqtMode::ConfAndAuth => ApqCiphersuite::default_pq_conf_and_auth(),
        }
    }
}

/// The APQMLS extension, which is used to store APQMLS-specific information
/// in the extensions of an [`openmls::group::MlsGroup`].
#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize, PartialEq, Eq)]
pub struct ApqMlsInfo {
    pub t_session_group_id: GroupId,
    pub pq_session_group_id: GroupId,
    pub mode: PqtMode,
    pub t_cipher_suite: Ciphersuite,
    pub pq_cipher_suite: Ciphersuite,
    pub t_epoch: GroupEpoch,
    pub pq_epoch: GroupEpoch,
}

impl ApqMlsInfo {
    pub(super) fn to_extension(&self) -> Result<Extension, tls_codec::Error> {
        self.tls_serialize_detached()?
            .pipe(UnknownExtension)
            .pipe(|extension| Extension::Unknown(APQMLS_EXTENSION_ID, extension))
            .pipe(Ok)
    }

    pub(super) fn set_epoch(&mut self, t_epoch: GroupEpoch, pq_epoch: GroupEpoch) {
        self.t_epoch = t_epoch;
        self.pq_epoch = pq_epoch;
    }

    pub fn from_extensions(
        extensions: &Extensions<GroupContext>,
    ) -> Result<Option<Self>, tls_codec::Error> {
        if let Some(extension) = extensions.unknown(APQMLS_EXTENSION_ID) {
            extension
                .0
                .pipe_as_ref::<'_, [u8], _>(ApqMlsInfo::tls_deserialize_exact)
                .map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn group_id(&self) -> ApqGroupId {
        ApqGroupId {
            t_group_id: self.t_session_group_id.clone(),
            pq_group_id: self.pq_session_group_id.clone(),
        }
    }
}

pub(super) fn ensure_extension_support(
    capabilities: Capabilities,
) -> Result<Capabilities, tls_codec::Error> {
    let mut extensions = capabilities.extensions().to_vec();
    if !extensions.contains(&APQMLS_EXTENSION_TYPE) {
        extensions.push(APQMLS_EXTENSION_TYPE);
    }
    if !extensions.contains(&ExtensionType::RequiredCapabilities) {
        extensions.push(ExtensionType::RequiredCapabilities);
    }
    let ciphersuites: Vec<Ciphersuite> = capabilities
        .ciphersuites()
        .iter()
        .map(|&cs| cs.try_into())
        .collect::<Result<_, _>>()?;
    Capabilities::new(
        Some(capabilities.versions()),
        Some(&ciphersuites),
        Some(extensions.as_slice()),
        Some(capabilities.proposals()),
        Some(capabilities.credentials()),
    )
    .pipe(Ok)
}

impl ApqMlsGroup {
    /// Get the APQMLS extension from the group, if it exists.
    pub fn apq_info(&self) -> Option<ApqMlsInfo> {
        ApqMlsInfo::from_extensions(self.t_group.extensions()).ok()?
    }
}
