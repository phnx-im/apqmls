// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{
        GroupContext, GroupEpoch, GroupId, MlsGroupBuilder, NewGroupError as OpenMlsNewGroupError,
        WireFormatPolicy,
    },
    prelude::{
        Capabilities, Extension, ExtensionType, Extensions, InvalidExtensionError, LeafNode,
        Lifetime, RequiredCapabilitiesExtension, SenderRatchetConfiguration,
    },
    storage::OpenMlsProvider,
    treesync::errors::LeafNodeValidationError,
};
use tap::Pipe as _;
use thiserror::Error;

use crate::{
    ApqCiphersuite, ApqGroupId, ApqMlsGroup,
    authentication::{ApqCredentialWithKey, ApqSigner},
    extension::{APQMLS_EXTENSION_TYPE, ApqMlsInfo, PqtMode, ensure_extension_support},
    key_package::ensure_ciphersuite_support,
};

/// Errors that can occur when creating a new [`ApqMlsGroup`].
#[derive(Error, Debug)]
pub enum NewGroupError<StorageError> {
    #[error(transparent)]
    NewGroup(#[from] OpenMlsNewGroupError<StorageError>),
    #[error("Error serializing APQInfo extension: {0}")]
    InvalidExtension(#[from] tls_codec::Error),
}

impl<StorageError> From<InvalidExtensionError> for NewGroupError<StorageError> {
    fn from(err: InvalidExtensionError) -> Self {
        OpenMlsNewGroupError::InvalidExtensions(err).into()
    }
}

/// A builder for creating a new [`ApqMlsGroup`].
#[derive(Debug, Default)]
pub struct GroupBuilder {
    t_group_builder: MlsGroupBuilder,
    pq_group_builder: MlsGroupBuilder,
    // We keep track of the values below so we can do some post-processing
    // later.
    group_ids: Option<ApqGroupId>,
    mode: PqtMode,
    capabilities: Capabilities,
    t_extensions: Extensions<GroupContext>,
    pq_extensions: Extensions<GroupContext>,
}

impl GroupBuilder {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Sets the [`PqtMode`] mode of the [`ApqMlsGroup`].
    pub fn set_mode(mut self, mode: PqtMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the group ID of the [`ApqMlsGroup`].
    pub fn with_group_ids(mut self, t_group_id: GroupId, pq_group_id: GroupId) -> Self {
        self.t_group_builder = self.t_group_builder.with_group_id(t_group_id.clone());
        self.pq_group_builder = self.pq_group_builder.with_group_id(pq_group_id.clone());
        self.group_ids = Some(ApqGroupId {
            t_group_id,
            pq_group_id,
        });
        self
    }

    /// Build a new group as configured by this builder.
    pub fn build<Provider: OpenMlsProvider>(
        mut self,
        provider: &Provider,
        signer: &impl ApqSigner,
        credential_with_key: ApqCredentialWithKey,
    ) -> Result<ApqMlsGroup, NewGroupError<Provider::StorageError>> {
        let ciphersuite = match self.mode {
            PqtMode::ConfOnly => ApqCiphersuite::default_pq_conf(),
            PqtMode::ConfAndAuth => ApqCiphersuite::default_pq_conf_and_auth(),
        };

        // Add extension to capabilities.
        let capabilities = self
            .capabilities
            .pipe(ensure_extension_support)?
            .pipe(|c| ensure_ciphersuite_support(c, ciphersuite))?;

        // Add extension to extensions
        let apq_group_id = self
            .group_ids
            .unwrap_or_else(|| ApqGroupId::random(provider.rand()));

        // Add required capabilities extension
        let rc_extension = RequiredCapabilitiesExtension::new(
            &[APQMLS_EXTENSION_TYPE, ExtensionType::RequiredCapabilities],
            &[],
            &[],
        )
        .pipe(Extension::RequiredCapabilities);

        self.t_extensions.add_or_replace(rc_extension.clone())?;
        self.pq_extensions.add_or_replace(rc_extension)?;

        let apq_mls_extension = ApqMlsInfo {
            t_session_group_id: apq_group_id.t_group_id.clone(),
            pq_session_group_id: apq_group_id.pq_group_id.clone(),
            mode: self.mode,
            t_cipher_suite: ciphersuite.t_ciphersuite,
            pq_cipher_suite: ciphersuite.pq_ciphersuite,
            t_epoch: GroupEpoch::from(0),
            pq_epoch: GroupEpoch::from(0),
        }
        .to_extension()?;

        self.t_extensions
            .add_or_replace(apq_mls_extension.clone())?;
        self.pq_extensions.add_or_replace(apq_mls_extension)?;

        let t_group = self
            .t_group_builder
            .ciphersuite(ciphersuite.t_ciphersuite)
            .with_group_context_extensions(self.t_extensions)
            .with_group_id(apq_group_id.t_group_id.clone())
            .with_capabilities(capabilities.clone())
            .build(
                provider,
                signer.t_signer(),
                credential_with_key.t_credential,
            )?;
        let pq_group = self
            .pq_group_builder
            .ciphersuite(ciphersuite.pq_ciphersuite)
            .with_group_context_extensions(self.pq_extensions)
            .with_group_id(apq_group_id.pq_group_id.clone())
            .with_capabilities(capabilities)
            .build(
                provider,
                signer.pq_signer(),
                credential_with_key.pq_credential,
            )?;

        Ok(ApqMlsGroup { pq_group, t_group })
    }

    // Builder options

    /// Sets the `wire_format` property of the ApqMlsGroup.
    pub fn with_wire_format_policy(mut self, wire_format_policy: WireFormatPolicy) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .with_wire_format_policy(wire_format_policy);
        self.pq_group_builder = self
            .pq_group_builder
            .with_wire_format_policy(wire_format_policy);
        self
    }

    /// Sets the `padding_size` property of the ApqMlsGroup.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.t_group_builder = self.t_group_builder.padding_size(padding_size);
        self.pq_group_builder = self.pq_group_builder.padding_size(padding_size);
        self
    }

    /// Sets the `max_past_epochs` property of the traditional MlsGroup.
    /// This allows application messages from previous epochs to be decrypted.
    ///
    /// **WARNING**
    ///
    /// This feature enables the storage of message secrets from past epochs.
    /// It is a trade-off between functionality and forward secrecy and should only be enabled
    /// if the Delivery Service cannot guarantee that application messages will be sent in
    /// the same epoch in which they were generated. The number for `max_epochs` should be
    /// as low as possible.
    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.t_group_builder = self.t_group_builder.max_past_epochs(max_past_epochs);
        // pq group is not used for application messages, so we don't set it there
        self
    }

    /// Sets the `number_of_resumption_psks` property of the ApqMlsGroup.
    pub fn number_of_resumption_psks(mut self, number_of_resumption_psks: usize) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .number_of_resumption_psks(number_of_resumption_psks);
        self.pq_group_builder = self
            .pq_group_builder
            .number_of_resumption_psks(number_of_resumption_psks);
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the MlsGroup.
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .use_ratchet_tree_extension(use_ratchet_tree_extension);
        self.pq_group_builder = self
            .pq_group_builder
            .use_ratchet_tree_extension(use_ratchet_tree_extension);
        self
    }

    /// Sets the `sender_ratchet_configuration` property of the traditional
    /// MlsGroup. See [`SenderRatchetConfiguration`] for more information.
    pub fn sender_ratchet_configuration(
        mut self,
        sender_ratchet_configuration: SenderRatchetConfiguration,
    ) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .sender_ratchet_configuration(sender_ratchet_configuration);
        // pq group does not use application messages, so we don't set the
        // configuration there
        self
    }

    /// Sets the `lifetime` of the group creator's leaf.
    pub fn lifetime(mut self, lifetime: Lifetime) -> Self {
        self.t_group_builder = self.t_group_builder.lifetime(lifetime);
        self.pq_group_builder = self.pq_group_builder.lifetime(lifetime);
        self
    }

    /// Sets the initial group context extensions
    pub fn with_group_context_extensions(
        mut self,
        t_extensions: Extensions<GroupContext>,
        pq_extensions: Extensions<GroupContext>,
    ) -> Result<Self, InvalidExtensionError> {
        self.t_extensions = t_extensions;
        self.pq_extensions = pq_extensions;
        // We set the extensions for both groups in `build`.
        Ok(self)
    }

    /// Sets the initial leaf node extensions
    pub fn with_leaf_node_extensions(
        mut self,
        t_extensions: Extensions<LeafNode>,
        pq_extensions: Extensions<LeafNode>,
    ) -> Result<Self, LeafNodeValidationError> {
        self.t_group_builder = self
            .t_group_builder
            .with_leaf_node_extensions(t_extensions)?;
        self.pq_group_builder = self
            .pq_group_builder
            .with_leaf_node_extensions(pq_extensions)?;
        Ok(self)
    }

    /// Sets the group creator's [`Capabilities`]
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities.clone();
        // We set the capabilities for both groups in `build`.
        self
    }
}
