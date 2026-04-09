// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{
        CommitBuilder as MlsGroupCommitBuilder, CommitBuilderStageError, CommitMessageBundle,
        CreateCommitError as OpenMlsCreateCommitError, GroupEpoch, Initial, QueuedProposal,
    },
    prelude::{
        InvalidExtensionError, LeafNodeIndex, LeafNodeParameters, PreSharedKeyProposal, Proposal,
        ProposalType,
    },
    storage::OpenMlsProvider,
};
use tap::Pipe as _;
use thiserror::Error;

use crate::{
    HpqMlsGroup,
    authentication::HpqSigner,
    messages::{HpqGroupInfo, HpqKeyPackage, HpqMlsMessageOut, HpqWelcome},
    psk::{HpqPskError, derive_and_store_psk},
};

/// Error while creating a commit in HPQMLS.
#[derive(Debug, Error)]
pub enum CreateCommitError<StorageError> {
    #[error("Failed to build commit: {0}")]
    BuildCommit(#[from] OpenMlsCreateCommitError),
    #[error("Failed to stage commit: {0}")]
    StageCommit(#[from] CommitBuilderStageError<StorageError>),
    #[error("Missing HPQInfo extension")]
    MissingHpqInfo,
    #[error("Malformed extension: {0}")]
    MalformedExtension(#[from] tls_codec::Error),
    #[error(transparent)]
    Psk(#[from] HpqPskError<StorageError>),
    #[error(transparent)]
    Extension(#[from] InvalidExtensionError),
}

/// A message bundle resulting from a commit operation in HPQMLS.
pub struct HpqCommitMessageBundle {
    pub commit: HpqMlsMessageOut,
    pub welcome: Option<HpqWelcome>,
    pub group_info: Option<HpqGroupInfo>,
}

impl HpqCommitMessageBundle {
    fn from_bundles(t_bundle: CommitMessageBundle, pq_bundle: CommitMessageBundle) -> Self {
        let (t_commit, t_welcome, t_group_info) = t_bundle.into_contents();
        let (pq_commit, pq_welcome, pq_group_info) = pq_bundle.into_contents();

        let commit = HpqMlsMessageOut {
            t_message: t_commit,
            pq_message: pq_commit,
        };

        let welcome = match (t_welcome, pq_welcome) {
            (Some(t), Some(pq)) => Some(HpqWelcome {
                t_welcome: t,
                pq_welcome: pq,
            }),
            (None, None) => None,
            _ => {
                debug_assert!(false, "Inconsistent welcome messages");
                None
            }
        };

        let group_info = t_group_info
            .zip(pq_group_info)
            .map(|(t_group_info, pq_group_info)| HpqGroupInfo {
                t_group_info,
                pq_group_info,
            });

        Self {
            commit,
            welcome,
            group_info,
        }
    }

    /// Consumes the bundle and returns the commit message.
    pub fn into_message_out(self) -> HpqMlsMessageOut {
        self.commit
    }

    /// Consumes the bundle and returns the welcome message, if any.
    pub fn into_welcome(self) -> Option<HpqWelcome> {
        self.welcome
    }

    /// Consumes the bundle and returns the group info, if any.
    pub fn into_group_info(self) -> Option<HpqGroupInfo> {
        self.group_info
    }
}

#[derive(Debug, Clone, Default)]
struct ConfigValues {
    consume_proposal_store: Option<bool>,
    // create_group_info: Option<bool>,
    force_self_update: Option<bool>,
    t_proposals: Vec<Proposal>,
    t_leaf_node_parameters: Option<LeafNodeParameters>,
    pq_leaf_node_parameters: Option<LeafNodeParameters>,
    proposed_adds: Vec<HpqKeyPackage>,
    proposed_removals: Vec<LeafNodeIndex>,
}

impl ConfigValues {
    fn apply<'b, const IS_TRADITIONAL: bool>(
        &self,
        mut builder: MlsGroupCommitBuilder<'b, Initial>,
    ) -> MlsGroupCommitBuilder<'b, Initial> {
        if let Some(consume) = self.consume_proposal_store {
            builder = builder.consume_proposal_store(consume);
        }
        // if let Some(create) = self.create_group_info {
        //     builder = builder.create_group_info(create);
        // }
        if let Some(force) = self.force_self_update {
            builder = builder.force_self_update(force);
        }
        if let Some(t_leaf_node_parameters) = &self.t_leaf_node_parameters {
            builder = builder.leaf_node_parameters(t_leaf_node_parameters.clone());
        }
        if let Some(pq_leaf_node_parameters) = &self.pq_leaf_node_parameters {
            builder = builder.leaf_node_parameters(pq_leaf_node_parameters.clone());
        }
        let (t_kps, pq_kps): (Vec<_>, Vec<_>) = self
            .proposed_adds
            .iter()
            .map(|kp| (kp.t_key_package.clone(), kp.pq_key_package.clone()))
            .unzip();
        if IS_TRADITIONAL {
            builder = builder.add_proposals(self.t_proposals.clone());
            builder = builder.propose_adds(t_kps);
        } else {
            builder = builder.propose_adds(pq_kps);
        }
        builder = builder.propose_removals(self.proposed_removals.clone());

        builder
    }
}

/// A builder for creating commits in an HPQMLS group. This builder can be used
/// to affect membership changes and issue full updates.
pub struct CommitBuilder<'a> {
    group: &'a mut HpqMlsGroup,
    values: ConfigValues,
}

impl<'a> CommitBuilder<'a> {
    /// returns a new [`CommitBuilder`] for the given [`openmls::group::MlsGroup`].
    pub fn new(group: &'a mut HpqMlsGroup) -> Self {
        Self {
            group,
            values: ConfigValues::default(),
        }
    }

    /// Sets whether or not the proposals in the proposal store of the group should be included in
    /// the commit. Defaults to `true`.
    pub fn consume_proposal_store(mut self, consume_proposal_store: bool) -> Self {
        self.values.consume_proposal_store = Some(consume_proposal_store);
        self
    }

    // /// Sets whether or not a [`openmls::messages::group_info::GroupInfo`] should be created when
    // /// the commit is staged. Defaults to the value of the [`openmls::group::MlsGroup`]s
    // /// [`openmls::group::MlsGroupJoinConfig`].
    // pub fn create_group_info(mut self, create_group_info: bool) -> Self {
    //     self.values.create_group_info = Some(create_group_info);
    //     self
    // }

    /// Sets whether or not the commit should force a self-update. Defaults to `false`.
    pub fn force_self_update(mut self, force_self_update: bool) -> Self {
        self.values.force_self_update = Some(force_self_update);
        self
    }

    /// Adds a proposal to the proposals to be committed in the traditional
    /// group. This must not be used with add or remove proposals.
    ///
    /// If this is used with add or remove proposals, the
    /// builder will return unchanged.
    pub fn add_t_proposal(mut self, t_proposal: Proposal) -> Self {
        if t_proposal.proposal_type() == ProposalType::Add
            || t_proposal.proposal_type() == ProposalType::Remove
        {
            return self;
        }
        self.values.t_proposals.push(t_proposal);
        self
    }

    /// Adds the proposals in the iterator to the proposals to be committed.
    /// None of the proposals may be of type Add or Remove.
    ///
    /// Any add or remove proposals are filtered out.
    pub fn add_t_proposals(mut self, t_proposals: impl IntoIterator<Item = Proposal>) -> Self {
        let iter = t_proposals.into_iter().filter(|p| {
            p.proposal_type() != ProposalType::Add && p.proposal_type() != ProposalType::Remove
        });
        self.values.t_proposals.extend(iter);
        self
    }

    /// Sets the leaf node parameters for the new leaf node in a self-update. Implies that a
    /// self-update takes place.
    pub fn leaf_node_parameters(
        mut self,
        t_leaf_node_parameters: LeafNodeParameters,
        pq_leaf_node_parameters: LeafNodeParameters,
    ) -> Self {
        self.values.t_leaf_node_parameters = Some(t_leaf_node_parameters);
        self.values.pq_leaf_node_parameters = Some(pq_leaf_node_parameters);
        self
    }

    /// Adds an Add proposal for each of the provided [`openmls::key_packages::KeyPackage`] tuples
    /// to the list of proposals to be committed. The first KeyPackage in each tuple must be the
    /// traditional one and the second the post-quantum one.
    pub fn propose_adds(mut self, key_packages: impl IntoIterator<Item = HpqKeyPackage>) -> Self {
        self.values.proposed_adds.extend(key_packages);
        self
    }

    /// Adds a Remove proposal for the provided [`LeafNodeIndex`]es to the list of proposals to be
    /// committed.
    pub fn propose_removals(mut self, removed: impl IntoIterator<Item = LeafNodeIndex>) -> Self {
        let removed = removed.into_iter().collect::<Vec<_>>();
        self.values.proposed_removals.extend(removed);
        self
    }

    /// Perform all steps to finish the builder.
    /// - load the PSKs for the PskProposals marked for inclusion
    /// - build the commit
    /// - stage the commit
    ///
    /// TODO: Split this up to enable sans-io usage.
    pub fn finalize<S: HpqSigner, Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        signer: &S,
        t_f: impl FnMut(&QueuedProposal) -> bool,
        pq_f: impl FnMut(&QueuedProposal) -> bool,
    ) -> Result<HpqCommitMessageBundle, CreateCommitError<Provider::StorageError>> {
        let mut current_hpq_info = self
            .group
            .hpq_info()
            .ok_or_else(|| CreateCommitError::MissingHpqInfo)?;
        let new_t_epoch = self.group.t_group.epoch().as_u64() + 1;
        let new_pq_epoch = self.group.pq_group.epoch().as_u64() + 1;
        current_hpq_info.set_epoch(
            GroupEpoch::from(new_t_epoch),
            GroupEpoch::from(new_pq_epoch),
        );

        let mut current_extensions = self.group.t_group.extensions().clone();
        current_extensions.add_or_replace(current_hpq_info.to_extension()?)?;

        // Create the PQ commit first s.t. we can export the PSK for the T group.
        let pq_result = self
            .group
            .pq_group
            .commit_builder()
            .pipe(|b| self.values.apply::<false>(b))
            .propose_group_context_extensions(current_extensions.clone())?
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer.pq_signer(), pq_f)?
            .stage_commit(provider)?;

        // Prepare the PSK for the T group.
        let psk_proposal = derive_and_store_psk::<_, true>(
            provider,
            &mut self.group.pq_group,
            self.group.t_group.ciphersuite(),
        )?
        .pipe(PreSharedKeyProposal::new)
        .pipe(Box::new)
        .pipe(Proposal::PreSharedKey);

        let t_result = self
            .group
            .t_group
            .commit_builder()
            .pipe(|b| self.values.apply::<true>(b))
            .add_proposal(psk_proposal)
            .propose_group_context_extensions(current_extensions)?
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer.t_signer(), t_f)?
            .stage_commit(provider)?;
        Ok(HpqCommitMessageBundle::from_bundles(t_result, pq_result))
    }
}
