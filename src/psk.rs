// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! This module defines types and functions for handling Pre-Shared Keys (PSKs)
//! in APQMLS.

use openmls::{
    group::{
        GroupId, MlsGroup, PendingSafeExportSecretError, ProcessedMessageSafeExportSecretError,
        SafeExportSecretError,
    },
    prelude::{Ciphersuite, CryptoError},
    schedule::{ExternalPsk, PreSharedKeyId, Psk, errors::PskError},
    storage::OpenMlsProvider,
};
use openmls_traits::storage::StorageProvider as _;
use tap::Pipe as _;
use thiserror::Error;
use tls_codec::{Serialize as _, TlsSerialize, TlsSize};

use crate::extension::APQMLS_EXTENSION_ID;

/// Error while handling PSKs in APQMLS.
#[derive(Debug, Error)]
pub enum ApqPskError<StorageError> {
    #[error(transparent)]
    ExportFromGroup(#[from] SafeExportSecretError<StorageError>),
    #[error(transparent)]
    ExportFromProcessed(#[from] ProcessedMessageSafeExportSecretError),
    #[error(transparent)]
    ExportFromPending(#[from] PendingSafeExportSecretError<StorageError>),
    #[error("Error deriving PSK ID: {0}")]
    DerivingPskId(#[from] CryptoError),
    #[error("OpenMLS PSK error: {0}")]
    Psk(#[from] PskError),
    #[error("Error serializing PSK ID: {0}")]
    SerializingPskId(#[from] tls_codec::Error),
}

/// The ID of a PSK in APQMLS, consisting of the group ID and epoch of the PQ
/// group.
#[derive(Debug, Clone, TlsSize, TlsSerialize)]
pub(crate) struct ApqPskId {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: u64,
}

pub(crate) fn derive_and_store_psk<
    Provider: openmls::storage::OpenMlsProvider,
    const FROM_PENDING: bool,
>(
    provider: &Provider,
    group: &mut MlsGroup,
    t_ciphersuite: Ciphersuite,
    //ciphersuite: Ciphersuite,
) -> Result<PreSharedKeyId, ApqPskError<Provider::StorageError>> {
    let (psk_value, epoch) = if FROM_PENDING {
        let psk_value = group.safe_export_secret_from_pending(
            provider.crypto(),
            provider.storage(),
            APQMLS_EXTENSION_ID,
        )?;
        let epoch = group.epoch().as_u64() + 1;
        (psk_value, epoch)
    } else {
        let psk_value =
            group.safe_export_secret(provider.crypto(), provider.storage(), APQMLS_EXTENSION_ID)?;
        (psk_value, group.epoch().as_u64())
    };
    // Prepare the PSK for the T group.
    ApqPskId {
        group_id: group.group_id().clone(),
        epoch,
    }
    .tls_serialize_detached()?
    .pipe(ExternalPsk::new)
    .pipe(Psk::External)
    .pipe(|psk| PreSharedKeyId::new(t_ciphersuite, provider.rand(), psk))?
    .pipe(|id| store_psk(provider, id, &psk_value))
}

pub(crate) fn store_psk<Provider: OpenMlsProvider>(
    provider: &Provider,
    psk_id: PreSharedKeyId,
    psk: &[u8],
) -> Result<PreSharedKeyId, ApqPskError<Provider::StorageError>> {
    // Delete any existing PSK with the same ID.
    provider
        .storage()
        .delete_psk::<Psk>(psk_id.psk())
        .map_err(|_| ApqPskError::Psk(PskError::Storage))?;
    psk_id.store(provider, psk)?;
    Ok(psk_id)
}
