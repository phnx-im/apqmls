// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt::Debug;

use openmls::{
    component::ComponentData,
    group::{AppDataUpdates, MlsGroup, ProcessMessageError, StagedCommit},
    prelude::{
        AppDataUpdateOperation, Credential, LeafNodeIndex, ProcessedMessage,
        ProcessedMessageContent, Proposal, ProposalIn, ProposalOrRefIn, ProposalType, Sender,
        UnverifiedMessage,
    },
    schedule::{PreSharedKeyId, Psk, psk::ApplicationPsk},
    storage::OpenMlsProvider,
};
use thiserror::Error;

use crate::{
    ApqMlsGroup,
    extension::{APQMLS_COMPONENT_ID, ApqInfo},
    messages::ApqProtocolMessage,
    psk::{ApqPskError, store_psk},
    secret::Secret,
};

/// A bundle consisting of the processed messages of both the traditional and
/// the PQ group.
pub struct ApqProcessedMessage {
    pub t_message: ProcessedMessage,
    pub pq_message: ProcessedMessage,
}

/// A bundle consisting of the staged commits of both the traditional and the
/// PQ group.
pub struct ApqStagedCommit {
    pub t_staged_commit: StagedCommit,
    pub pq_staged_commit: StagedCommit,
}

impl ApqProcessedMessage {
    pub fn into_staged_commit(self) -> Option<ApqStagedCommit> {
        let t_staged_commit = match self.t_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
            _ => return None,
        };
        let pq_staged_commit = match self.pq_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
            _ => return None,
        };
        Some(ApqStagedCommit {
            t_staged_commit,
            pq_staged_commit,
        })
    }
}

/// Errors that can occur when processing a message with an [`ApqMlsGroup`].
#[derive(Debug, Error)]
pub enum ApqProcessMessageError<StorageError> {
    #[error("Failed to process message: {0}")]
    Processing(#[from] ProcessMessageError<StorageError>),
    #[error(transparent)]
    Psk(#[from] ApqPskError<StorageError>),
    #[error("The message type is invalid for processing.")]
    InvalidMessageType,
    #[error("The MLS messages don't match.")]
    MismatchedMessages,
    #[error("APQInfo extension is missing or invalid in commit message.")]
    MissingApqInfo,
    #[error("APQInfo extension content is invalid.")]
    InvalidApqInfo,
}

#[derive(Eq)]
enum MessageType<F: Fn(&Credential, &Credential) -> bool> {
    Proposal(ProposalContent<F>),
    Commit(CommitContent<F>),
}

impl<F: Fn(&Credential, &Credential) -> bool> Debug for MessageType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Proposal(proposal) => f
                .debug_struct("Proposal")
                .field("proposal_type", &proposal.proposal_type)
                .field("credential", &proposal.credential)
                .field("leaf_index", &proposal.leaf_index)
                .finish(),
            MessageType::Commit(commit) => f
                .debug_struct("Commit")
                .field("adds", &commit.adds)
                .field("removes", &commit.removes)
                .field("updates", &commit.updates)
                .finish(),
        }
    }
}

impl<F: Fn(&Credential, &Credential) -> bool> MessageType<F> {
    fn new(processed_message: &ProcessedMessageContent, compare: F) -> Option<Self> {
        match processed_message {
            ProcessedMessageContent::ApplicationMessage(_) => None,
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                let proposal = queued_proposal.proposal();
                let proposal_type = proposal.proposal_type();
                let (credential, leaf_index) = match proposal {
                    Proposal::Add(add_proposal) => (
                        Some(add_proposal.key_package().leaf_node().credential().clone()),
                        None,
                    ),
                    Proposal::Update(update_proposal) => {
                        (Some(update_proposal.leaf_node().credential().clone()), None)
                    }
                    Proposal::Remove(remove_proposal) => (None, Some(remove_proposal.removed())),
                    _ => (None, None),
                };
                Some(MessageType::Proposal(ProposalContent {
                    proposal_type,
                    credential,
                    leaf_index,
                    compare,
                }))
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(queued_proposal) => {
                let proposal = queued_proposal.proposal();
                let proposal_type = proposal.proposal_type();
                let credential = if let Proposal::Add(add_proposal) = proposal {
                    Some(add_proposal.key_package().leaf_node().credential().clone())
                } else {
                    None
                };
                Some(MessageType::Proposal(ProposalContent {
                    proposal_type,
                    credential,
                    leaf_index: None,
                    compare,
                }))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let adds = staged_commit
                    .add_proposals()
                    .map(|p| {
                        p.add_proposal()
                            .key_package()
                            .leaf_node()
                            .credential()
                            .clone()
                    })
                    .collect();
                let removes = staged_commit
                    .remove_proposals()
                    .map(|p| p.remove_proposal().removed())
                    .collect();
                let updates = staged_commit
                    .update_proposals()
                    .map(|p| p.update_proposal().leaf_node().credential().clone())
                    .collect();
                let path_credential = staged_commit
                    .update_path_leaf_node()
                    .map(|node| node.credential().clone());
                Some(MessageType::Commit(CommitContent {
                    path_credential,
                    adds,
                    removes,
                    updates,
                    compare,
                }))
            }
        }
    }
}

#[derive(Debug, Eq)]
struct ProposalContent<F: Fn(&Credential, &Credential) -> bool> {
    proposal_type: ProposalType,
    credential: Option<Credential>,
    leaf_index: Option<LeafNodeIndex>,
    compare: F,
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for ProposalContent<F> {
    fn eq(&self, other: &Self) -> bool {
        let same_credential = match (&self.credential, &other.credential) {
            (Some(a), Some(b)) => (self.compare)(a, b),
            (None, None) => true,
            _ => false,
        };
        self.proposal_type == other.proposal_type
            && self.leaf_index == other.leaf_index
            && same_credential
    }
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for MessageType<F> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MessageType::Proposal(a), MessageType::Proposal(b)) => a == b,
            (MessageType::Commit(a), MessageType::Commit(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, Eq)]
struct CommitContent<F: Fn(&Credential, &Credential) -> bool> {
    path_credential: Option<Credential>,
    adds: Vec<Credential>,
    removes: Vec<LeafNodeIndex>,
    updates: Vec<Credential>,
    compare: F,
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for CommitContent<F> {
    fn eq(&self, other: &Self) -> bool {
        let same_path_credential = match (&self.path_credential, &other.path_credential) {
            (Some(a), Some(b)) => (self.compare)(a, b),
            (None, None) => true,
            _ => false,
        };
        same_path_credential
            && self.removes == other.removes
            && self.adds.len() == other.adds.len()
            && self.updates.len() == other.updates.len()
            && self
                .adds
                .iter()
                .zip(&other.adds)
                .all(|(a, b)| (self.compare)(a, b))
            && self
                .updates
                .iter()
                .zip(&other.updates)
                .all(|(a, b)| (self.compare)(a, b))
    }
}

#[derive(Eq)]
struct MessageInfo<F: Fn(&Credential, &Credential) -> bool> {
    msg_type: MessageType<F>,
    sender: Sender,
}

impl<F: Fn(&Credential, &Credential) -> bool> Debug for MessageInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageInfo")
            .field("msg_type", &self.msg_type)
            .field("sender", &self.sender)
            .finish()
    }
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for MessageInfo<F> {
    fn eq(&self, other: &Self) -> bool {
        self.msg_type == other.msg_type && self.sender == other.sender
    }
}

impl ApqMlsGroup {
    /// See the free function [`process_message`].
    pub fn process_message<F, Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ApqProtocolMessage>,
        sender_equivalence: F,
    ) -> Result<ApqProcessedMessage, ApqProcessMessageError<Provider::StorageError>>
    where
        F: Fn(&Credential, &Credential) -> bool,
    {
        process_message(
            &mut self.t_group,
            &mut self.pq_group,
            provider,
            message,
            sender_equivalence,
        )
    }
}

/// Processes an incoming APQMLS message.
///
/// Parses incoming messages from the DS. Checks for syntactic errors and makes some semantic checks
/// as well. If the input is an encrypted message, it will be decrypted. This processing function
/// does syntactic and semantic validation of the message. It returns a [ProcessedMessage] enum.
///
/// # Errors
///
/// Returns an [`ProcessMessageError`] when the validation checks fail with the exact reason of the
/// failure.
pub fn process_message<F, Provider: OpenMlsProvider>(
    t_group: &mut MlsGroup,
    pq_group: &mut MlsGroup,
    provider: &Provider,
    message: impl Into<ApqProtocolMessage>,
    sender_equivalence: F,
) -> Result<ApqProcessedMessage, ApqProcessMessageError<Provider::StorageError>>
where
    F: Fn(&Credential, &Credential) -> bool,
{
    let protocol_message: ApqProtocolMessage = message.into();
    // We only export a PSK if we process a PQ message
    let unverified_pq_message =
        pq_group.unprotect_message(provider, protocol_message.pq_protocol_message)?;
    let pq_updates = extract_app_data_updates(pq_group, &unverified_pq_message);
    let mut pq_message = pq_group.process_unverified_message_with_app_data_updates(
        provider,
        unverified_pq_message,
        pq_updates,
    )?;

    let msg_type = MessageType::new(pq_message.content(), &sender_equivalence)
        .ok_or(ApqProcessMessageError::InvalidMessageType)?;
    let pq_message_info = MessageInfo {
        msg_type,
        sender: pq_message.sender().clone(),
    };

    // If we have a commit message, we need to export the PSK
    if matches!(
        pq_message.content(),
        ProcessedMessageContent::StagedCommitMessage(_)
    ) {
        let apq_exporter: Secret = pq_message
            .safe_export_secret(provider.crypto(), APQMLS_COMPONENT_ID)
            .map_err(ApqPskError::ExportFromProcessed)?
            .into();

        let apq_psk_id = apq_exporter
            .derive_secret(provider.crypto(), t_group.ciphersuite(), "psk_id")
            .map_err(ApqPskError::DerivingPskId)?;
        let apq_psk = apq_exporter
            .derive_secret(provider.crypto(), t_group.ciphersuite(), "psk")
            .map_err(ApqPskError::DerivingPskId)?;
        drop(apq_exporter); // Zeroize the secret

        let psk = Psk::Application(ApplicationPsk::new(
            APQMLS_COMPONENT_ID,
            apq_psk_id.as_slice().into(),
        ));
        let id = PreSharedKeyId::new(t_group.ciphersuite(), provider.rand(), psk)
            .map_err(ApqPskError::DerivingPskId)?;
        store_psk(provider, id, apq_psk.as_slice())?;
    }

    let unverified_t_message =
        t_group.unprotect_message(provider, protocol_message.t_protocol_message)?;
    let t_updates = extract_app_data_updates(t_group, &unverified_t_message);
    let t_message = t_group.process_unverified_message_with_app_data_updates(
        provider,
        unverified_t_message,
        t_updates,
    )?;

    let msg_type = MessageType::new(t_message.content(), &sender_equivalence)
        .ok_or(ApqProcessMessageError::InvalidMessageType)?;
    let t_message_info = MessageInfo {
        msg_type,
        sender: t_message.sender().clone(),
    };

    // Make sure that messages match up
    if pq_message_info != t_message_info {
        return Err(ApqProcessMessageError::MismatchedMessages);
    }

    // If both are commits, the [`ApqInfo`] component must be updated and in
    // line with the info of both groups
    if let ProcessedMessageContent::StagedCommitMessage(pq_staged_commit) = pq_message.content()
        && let ProcessedMessageContent::StagedCommitMessage(t_staged_commit) = t_message.content()
    {
        let pq_apq_info = ApqInfo::from_extensions(pq_staged_commit.group_context().extensions())
            .map_err(|_| ApqProcessMessageError::InvalidApqInfo)?
            .ok_or(ApqProcessMessageError::MissingApqInfo)?;
        let t_apq_info = ApqInfo::from_extensions(t_staged_commit.group_context().extensions())
            .map_err(|_| ApqProcessMessageError::InvalidApqInfo)?
            .ok_or(ApqProcessMessageError::MissingApqInfo)?;

        // ApqInfo contents must match
        let apq_info_match = pq_apq_info == t_apq_info;

        // Epochs must be in line with the groups
        let epochs_match = pq_apq_info.pq_epoch == pq_staged_commit.group_context().epoch()
            && t_apq_info.t_epoch == t_staged_commit.group_context().epoch();

        // New epochs must be one higher than the current ones
        let epochs_are_incremented = pq_apq_info.pq_epoch.as_u64() == pq_group.epoch().as_u64() + 1
            && t_apq_info.t_epoch.as_u64() == t_group.epoch().as_u64() + 1;

        // Group IDs must be in line with the groups
        let group_ids_match = pq_apq_info.pq_session_group_id == *pq_group.group_id()
            && t_apq_info.t_session_group_id == *t_group.group_id();

        // Ciphersuites must be in line with the groups
        let ciphersuites_match = pq_apq_info.pq_cipher_suite == pq_group.ciphersuite()
            && t_apq_info.t_cipher_suite == t_group.ciphersuite();

        if !apq_info_match
            || !epochs_match
            || !epochs_are_incremented
            || !group_ids_match
            || !ciphersuites_match
        {
            return Err(ApqProcessMessageError::InvalidApqInfo);
        }
    }

    Ok(ApqProcessedMessage {
        t_message,
        pq_message,
    })
}

fn extract_app_data_updates(
    group: &MlsGroup,
    unverified: &UnverifiedMessage,
) -> Option<AppDataUpdates> {
    let mut updater = group.app_data_dictionary_updater();
    let mut updated = false;
    for proposal in unverified.committed_proposals()? {
        if let ProposalOrRefIn::Proposal(p) = proposal
            && let ProposalIn::AppDataUpdate(p) = &**p
        {
            match p.operation() {
                AppDataUpdateOperation::Update(data) => {
                    updater.set(ComponentData::from_parts(p.component_id(), data.clone()));
                }
                AppDataUpdateOperation::Remove => {
                    updater.remove(&p.component_id());
                }
            }
            updated = true;
        }
    }
    updated.then(|| updater.changes()).flatten()
}
