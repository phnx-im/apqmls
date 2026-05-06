// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{
        JoinBuilder as OpenMlsJoinBuilder, LeafNodeLifetimePolicy, MlsGroup, MlsGroupJoinConfig,
        ProcessedWelcome, StagedWelcome, WelcomeError as OpenMlsWelcomeError,
    },
    prelude::Ciphersuite,
    storage::OpenMlsProvider,
};
use thiserror::Error;

use crate::{
    ApqMlsGroup,
    messages::{ApqRatchetTreeIn, ApqWelcome},
    psk::{ApqPskError, derive_and_store_psk},
};

/// Errors that can occur when creating a new [`ApqMlsGroup`] from a welcome
/// message.
#[derive(Debug, Error)]
pub enum WelcomeError<StorageError> {
    #[error("Failed to process welcome message: {0}")]
    Processing(#[from] OpenMlsWelcomeError<StorageError>),
    #[error(transparent)]
    Psk(#[from] ApqPskError<StorageError>),
}

/// A staged APQ welcome.
pub struct StagedApqWelcome {
    t_staged_welcome: StagedWelcome,
    pq_staged_welcome: StagedWelcome,
}

/// Builder for joining an APQ group.
pub struct JoinBuilder<'a, Provider: OpenMlsProvider> {
    provider: &'a Provider,
    t_processed_welcome: ProcessedWelcome,
    pq_processed_welcome: ProcessedWelcome,
    t_ciphersuite: Ciphersuite,
    ratchet_tree: Option<ApqRatchetTreeIn>,
    validate_lifetimes: LeafNodeLifetimePolicy,
}

impl<'a, Provider: OpenMlsProvider> JoinBuilder<'a, Provider> {
    pub fn new(
        provider: &'a Provider,
        t_processed_welcome: ProcessedWelcome,
        pq_processed_welcome: ProcessedWelcome,
        t_ciphersuite: Ciphersuite,
    ) -> Self {
        Self {
            provider,
            t_processed_welcome,
            pq_processed_welcome,
            t_ciphersuite,
            ratchet_tree: None,
            validate_lifetimes: LeafNodeLifetimePolicy::Verify,
        }
    }

    pub fn with_ratchet_tree(mut self, ratchet_tree: ApqRatchetTreeIn) -> Self {
        self.ratchet_tree = Some(ratchet_tree);
        self
    }

    pub fn skip_lifetime_validation(mut self) -> Self {
        self.validate_lifetimes = LeafNodeLifetimePolicy::Skip;
        self
    }

    pub fn build(self) -> Result<ApqMlsGroup, WelcomeError<Provider::StorageError>> {
        let (t_ratchet_tree, pq_ratchet_tree) = self.ratchet_tree.map(|t| t.split()).unzip();

        let mut pq_builder = OpenMlsJoinBuilder::new(self.provider, self.pq_processed_welcome);
        if let Some(ratchet_tree) = pq_ratchet_tree {
            pq_builder = pq_builder.with_ratchet_tree(ratchet_tree);
        };
        pq_builder = match self.validate_lifetimes {
            LeafNodeLifetimePolicy::Skip => pq_builder.skip_lifetime_validation(),
            LeafNodeLifetimePolicy::Verify => pq_builder,
        };
        let mut pq_group = pq_builder.build()?.into_group(self.provider)?;

        derive_and_store_psk::<_, false>(self.provider, &mut pq_group, self.t_ciphersuite)?;

        let mut t_builder = OpenMlsJoinBuilder::new(self.provider, self.t_processed_welcome);
        if let Some(ratchet_tree) = t_ratchet_tree {
            t_builder = t_builder.with_ratchet_tree(ratchet_tree);
        };
        t_builder = match self.validate_lifetimes {
            LeafNodeLifetimePolicy::Skip => t_builder.skip_lifetime_validation(),
            LeafNodeLifetimePolicy::Verify => t_builder,
        };
        let t_group = t_builder.build()?.into_group(self.provider)?;

        Ok(ApqMlsGroup { t_group, pq_group })
    }
}

pub fn derive_and_store_join_psk<Provider: OpenMlsProvider>(
    provider: &Provider,
    pq_group: &mut MlsGroup,
    t_ciphersuite: Ciphersuite,
) -> Result<(), WelcomeError<Provider::StorageError>> {
    derive_and_store_psk::<_, false>(provider, pq_group, t_ciphersuite)?;
    Ok(())
}

impl ApqMlsGroup {
    /// Creates a new [`ApqMlsGroup`] from a welcome message.
    // TODO: Split into sans-io friendly parts.
    pub fn new_from_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: ApqWelcome,
        ratchet_tree: Option<ApqRatchetTreeIn>,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let (t_ratchet_tree, pq_ratchet_tree) = match ratchet_tree {
            Some(r) => (Some(r.t_ratchet_tree), Some(r.pq_ratchet_tree)),
            None => (None, None),
        };
        let mut pq_group = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.pq_welcome,
            pq_ratchet_tree,
        )?
        .into_group(provider)?;

        let t_ciphersuite = welcome.t_welcome.ciphersuite();

        derive_and_store_psk::<_, false>(provider, &mut pq_group, t_ciphersuite)?;

        let t_group = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.t_welcome,
            t_ratchet_tree,
        )?
        .into_group(provider)?;

        Ok(Self { t_group, pq_group })
    }
}

impl StagedApqWelcome {
    /// Creates a new [`StagedApqWelcome`] from a welcome message.
    pub fn new_from_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: ApqWelcome,
        ratchet_tree: Option<ApqRatchetTreeIn>,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let (t_ratchet_tree, pq_ratchet_tree) = match ratchet_tree {
            Some(r) => (Some(r.t_ratchet_tree), Some(r.pq_ratchet_tree)),
            None => (None, None),
        };
        let t_staged_welcome = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.t_welcome,
            t_ratchet_tree,
        )?;
        let pq_staged_welcome = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.pq_welcome,
            pq_ratchet_tree,
        )?;

        Ok(StagedApqWelcome {
            t_staged_welcome,
            pq_staged_welcome,
        })
    }

    /// Consumes the staged welcome and creates a new [`ApqMlsGroup`].
    pub fn into_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<ApqMlsGroup, WelcomeError<Provider::StorageError>> {
        let t_group = self.t_staged_welcome.into_group(provider)?;
        let pq_group = self.pq_staged_welcome.into_group(provider)?;

        Ok(ApqMlsGroup { t_group, pq_group })
    }
}
