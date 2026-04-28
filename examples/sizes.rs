// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Measures message sizes and CBOR-encoded storage size of APQ MLS group state
//! across ciphersuites and group sizes.
//!
//! Run with: `cargo run --example sizes`

use std::{
    convert::Infallible,
    ops::{Add, Div},
};

use apqmls::{
    ApqCiphersuite, ApqMlsGroup,
    authentication::{ApqCredentialWithKey, ApqSignatureKeyPair},
    extension::PqtMode,
    messages::{ApqKeyPackage, ApqMlsMessageIn, ApqMlsMessageOut},
};
use indicatif::{ProgressBar, ProgressStyle};
use openmls::{
    group::MlsGroupJoinConfig,
    prelude::{Ciphersuite, Credential, OpenMlsProvider},
};
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use rayon::prelude::*;
use serde::Serialize;
use tls_codec::{Deserialize as _, Serialize as _};
use tracing::{info, instrument};

const GROUP_SIZES: &[usize] = &[100];

#[derive(Default)]
struct StorageSize {
    full_db: usize,
    group_data: GroupDataSize,
}

#[derive(Default, Debug)]
struct GroupDataSize {
    application_export_tree: usize,
    confirmation_tag: usize,
    context: usize,
    group_epoch_secrets: usize,
    group_state: usize,
    interim_transcript_hash: usize,
    join_group_config: usize,
    message_secrets: usize,
    own_leaf_index: usize,
    resumption_psk_store: usize,
    tree: usize,
}

impl Add<GroupDataSize> for GroupDataSize {
    type Output = GroupDataSize;

    fn add(self, rhs: GroupDataSize) -> Self::Output {
        Self {
            application_export_tree: self.application_export_tree + rhs.application_export_tree,
            confirmation_tag: self.confirmation_tag + rhs.confirmation_tag,
            context: self.context + rhs.context,
            group_epoch_secrets: self.group_epoch_secrets + rhs.group_epoch_secrets,
            group_state: self.group_state + rhs.group_state,
            interim_transcript_hash: self.interim_transcript_hash + rhs.interim_transcript_hash,
            join_group_config: self.join_group_config + rhs.join_group_config,
            message_secrets: self.message_secrets + rhs.message_secrets,
            own_leaf_index: self.own_leaf_index + rhs.own_leaf_index,
            resumption_psk_store: self.resumption_psk_store + rhs.resumption_psk_store,
            tree: self.tree + rhs.tree,
        }
    }
}

impl Div<usize> for GroupDataSize {
    type Output = GroupDataSize;

    fn div(self, rhs: usize) -> Self::Output {
        Self {
            application_export_tree: self.application_export_tree / rhs,
            confirmation_tag: self.confirmation_tag / rhs,
            context: self.context / rhs,
            group_epoch_secrets: self.group_epoch_secrets / rhs,
            group_state: self.group_state / rhs,
            interim_transcript_hash: self.interim_transcript_hash / rhs,
            join_group_config: self.join_group_config / rhs,
            message_secrets: self.message_secrets / rhs,
            own_leaf_index: self.own_leaf_index / rhs,
            resumption_psk_store: self.resumption_psk_store / rhs,
            tree: self.tree / rhs,
        }
    }
}

impl Add<StorageSize> for StorageSize {
    type Output = StorageSize;

    fn add(self, rhs: StorageSize) -> Self::Output {
        Self {
            full_db: self.full_db + rhs.full_db,
            group_data: self.group_data + rhs.group_data,
        }
    }
}

impl Div<usize> for StorageSize {
    type Output = StorageSize;

    fn div(self, rhs: usize) -> Self::Output {
        Self {
            full_db: self.full_db / rhs,
            group_data: self.group_data / rhs,
        }
    }
}

/// Returns the CBOR-encoded size of all key-value pairs in the provider's storage.
fn storage_size(connection: &mut rusqlite::Connection) -> StorageSize {
    let mut stmt = connection
        .prepare(
            "SELECT data_type, SUM(LENGTH(group_data))
            FROM openmls_group_data
            GROUP BY data_type
            ORDER BY data_type",
        )
        .unwrap();

    let mut sizes = StorageSize::default();

    for row in stmt
        .query_map([], |row| {
            let data_type: String = row.get(0)?;
            let size: i64 = row.get(1)?;
            Ok((data_type, size))
        })
        .unwrap()
    {
        let (data_type, size) = row.unwrap();
        match data_type.as_str() {
            "application_export_tree" => sizes.group_data.application_export_tree = size as usize,
            "confirmation_tag" => sizes.group_data.confirmation_tag = size as usize,
            "context" => sizes.group_data.context = size as usize,
            "group_epoch_secrets" => sizes.group_data.group_epoch_secrets = size as usize,
            "group_state" => sizes.group_data.group_state = size as usize,
            "interim_transcript_hash" => sizes.group_data.interim_transcript_hash = size as usize,
            "join_group_config" => sizes.group_data.join_group_config = size as usize,
            "message_secrets" => sizes.group_data.message_secrets = size as usize,
            "own_leaf_index" => sizes.group_data.own_leaf_index = size as usize,
            "resumption_psk_store" => sizes.group_data.resumption_psk_store = size as usize,
            "tree" => sizes.group_data.tree = size as usize,
            _ => {}
        }
    }

    let mut stmt = connection.prepare("PRAGMA page_count").unwrap();
    let page_count: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
    let mut stmt = connection.prepare("PRAGMA page_size").unwrap();
    let page_size: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
    sizes.full_db = (page_count * page_size).try_into().unwrap();

    sizes
}

fn commify(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

struct SizeReport {
    label: &'static str,
    group_size: usize,
    key_package_bytes: usize,
    add_commit_bytes: usize,
    welcome_bytes: usize,
    update_commit_bytes: usize,
    creator_storage_bytes: StorageSize,
    member_storage_bytes: StorageSize,
}

struct Provider<'c> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<CborCodec, &'c mut rusqlite::Connection>,
}

impl<'c> Provider<'c> {
    fn new(connection: &'c mut rusqlite::Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(connection),
        }
    }
}

#[derive(Default)]
struct CborCodec {}

impl Codec for CborCodec {
    type Error = Infallible;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        let mut vec = Vec::new();
        ciborium::into_writer(value, &mut vec).unwrap();
        Ok(vec)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        Ok(ciborium::from_reader(slice).unwrap())
    }
}

impl<'c> OpenMlsProvider for Provider<'c> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<CborCodec, &'c mut rusqlite::Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

struct Client {
    signer: ApqSignatureKeyPair,
    cred: ApqCredentialWithKey,
    connection: rusqlite::Connection,
    group: Option<ApqMlsGroup>,
}

impl Client {
    fn process_commit(&mut self, commit: &ApqMlsMessageOut) {
        let provider = Provider::new(&mut self.connection);
        let group = self.group.as_mut().unwrap();
        process_commit(group, &provider, commit);
    }

    fn self_update(&mut self) -> ApqMlsMessageOut {
        let provider = Provider::new(&mut self.connection);
        let group = self.group.as_mut().unwrap();
        member_self_update(group, &provider, &self.signer)
    }
}

fn new_client(name: &str, ciphersuite: ApqCiphersuite) -> Client {
    let mut connection = rusqlite::Connection::open_in_memory().unwrap();
    let mut provider = Provider::new(&mut connection);
    provider.storage.run_migrations().unwrap();

    let signer = ApqSignatureKeyPair::new(ciphersuite.into()).unwrap();
    let cred = ApqCredentialWithKey::new(name.as_bytes(), &signer);
    Client {
        signer,
        cred,
        connection,
        group: None,
    }
}

fn process_commit(group: &mut ApqMlsGroup, provider: &Provider, commit: &ApqMlsMessageOut) {
    let msg_in = ApqMlsMessageIn::try_from(commit.clone()).unwrap();
    let protocol_msg = msg_in.into_protocol_message().unwrap();
    let processed = group
        .process_message(
            provider,
            protocol_msg,
            |c1: &Credential, c2: &Credential| c1 == c2,
        )
        .unwrap();
    group
        .merge_staged_commit(provider, processed.into_staged_commit().unwrap())
        .unwrap();
}

fn member_self_update(
    group: &mut ApqMlsGroup,
    provider: &Provider<'_>,
    signer: &ApqSignatureKeyPair,
) -> ApqMlsMessageOut {
    let bundle = group
        .commit_builder()
        .force_self_update(true)
        .finalize(provider, signer, |_| true, |_| true)
        .unwrap();
    group.merge_pending_commit(provider).unwrap();
    bundle.commit
}

#[instrument(skip(pb, mode, ciphersuite))]
fn measure(
    mode: PqtMode,
    ciphersuite: ApqCiphersuite,
    group_size: usize,
    label: &'static str,
    pb: &ProgressBar,
) -> SizeReport {
    info!("Measuring {label} with {group_size} members");

    let mut clients = Vec::with_capacity(group_size);

    let mut creator_client = new_client("alice", ciphersuite);
    let creator_provider = Provider::new(&mut creator_client.connection);
    creator_client.group = Some(
        ApqMlsGroup::builder()
            .set_mode(mode)
            .with_ciphersuite(ciphersuite)
            .build(
                &creator_provider,
                &creator_client.signer,
                creator_client.cred.clone(),
            )
            .unwrap(),
    );
    clients.push(creator_client);
    info!("Creator group built");

    let mut last_kp_bytes = 0usize;
    let mut last_add_commit_bytes = 0usize;
    let mut last_welcome_bytes = 0usize;

    // Create all member clients and their key packages upfront
    let mut kps = vec![];

    for i in 1..group_size {
        let mut member_client = new_client(&format!("member-{i}"), ciphersuite);
        let member_provider = Provider::new(&mut member_client.connection);

        let kp = ApqKeyPackage::builder()
            .build(
                &member_provider,
                ciphersuite,
                &member_client.signer,
                member_client.cred.clone(),
            )
            .unwrap()
            .into_key_package();

        last_kp_bytes = ApqMlsMessageOut::from(kp.clone())
            .tls_serialize_detached()
            .unwrap()
            .len();

        kps.push(kp);
        clients.push(member_client);
    }
    info!("Key packages built");

    // Add all members in a single commit
    if !kps.is_empty() {
        let creator_client = &mut clients[0];
        let creator_provider = Provider::new(&mut creator_client.connection);
        let creator_group = creator_client.group.as_mut().unwrap();
        let bundle = creator_group
            .commit_builder()
            .propose_adds(kps)
            .finalize(
                &creator_provider,
                &creator_client.signer,
                |_| true,
                |_| true,
            )
            .unwrap();
        creator_group
            .merge_pending_commit(&creator_provider)
            .unwrap();

        last_add_commit_bytes = bundle.commit.tls_serialize_detached().unwrap().len();

        let welcome_out = ApqMlsMessageOut::from(bundle.welcome.unwrap());
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();
        last_welcome_bytes = welcome_bytes.len();

        let ratchet_tree = creator_group.export_ratchet_tree();

        for client in clients.iter_mut().skip(1) {
            let welcome = ApqMlsMessageIn::tls_deserialize_exact(&welcome_bytes[..])
                .unwrap()
                .into_welcome()
                .unwrap();
            let provider = Provider::new(&mut client.connection);
            let member_group = ApqMlsGroup::new_from_welcome(
                &provider,
                &MlsGroupJoinConfig::default(),
                welcome,
                Some(ratchet_tree.clone().into()),
            )
            .unwrap();
            client.group = Some(member_group);
        }
    }
    info!("Member groups built");

    // One self-update per member; creator and other members process each commit
    let mut update_commit_total = 0usize;
    for i in 1..clients.len() {
        let commit = clients[i].self_update();

        update_commit_total += commit.tls_serialize_detached().unwrap().len();

        // Process the commit for the creator group
        clients[0].process_commit(&commit);
        pb.inc(1);

        // Process the commit for the members *after* this member
        clients.par_iter_mut().skip(i + 1).for_each(|client| {
            client.process_commit(&commit);
            pb.inc(1);
        });
    }
    info!("Updates processed");

    let creator_storage_bytes = storage_size(&mut clients[0].connection);
    let member_storage_bytes = if clients.is_empty() {
        StorageSize::default()
    } else {
        clients
            .iter_mut()
            .skip(1)
            .map(|client| storage_size(&mut client.connection))
            .fold(StorageSize::default(), |a, b| a + b)
            / (clients.len() - 1)
    };
    info!("Storage sizes computed");

    SizeReport {
        label,
        group_size,
        key_package_bytes: last_kp_bytes,
        add_commit_bytes: last_add_commit_bytes,
        welcome_bytes: last_welcome_bytes,
        update_commit_bytes: if clients.is_empty() {
            0
        } else {
            update_commit_total / (clients.len() - 1)
        },
        creator_storage_bytes,
        member_storage_bytes,
    }
}

fn main() {
    tracing_subscriber::fmt::fmt()
        .with_writer(std::io::stderr)
        .init();

    const T_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

    let configs: &[(&'static str, PqtMode, ApqCiphersuite)] = &[
        (
            "TBD2 MLKEM768X25519_AES256GCM_SHA384_Ed25519",
            PqtMode::ConfOnly,
            ApqCiphersuite::new(
                T_CIPHERSUITE,
                Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            ),
        ),
        (
            "TBD6 MLKEM768_AES256GCM_SHA384_P256",
            PqtMode::ConfOnly,
            ApqCiphersuite::new(
                T_CIPHERSUITE,
                Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            ),
        ),
        (
            "TBD7 MLKEM1024_AES256GCM_SHA384_P384",
            PqtMode::ConfOnly,
            ApqCiphersuite::new(
                T_CIPHERSUITE,
                Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            ),
        ),
        (
            "TBD8 MLKEM768_AES256GCM_SHA384_MLDSA65",
            PqtMode::ConfAndAuth,
            ApqCiphersuite::new(
                T_CIPHERSUITE,
                Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            ),
        ),
        (
            "TBD9 MLKEM1024_AES256GCM_SHA384_MLDSA87",
            PqtMode::ConfAndAuth,
            ApqCiphersuite::new(
                T_CIPHERSUITE,
                Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            ),
        ),
    ];

    // Collect all results first
    let tasks: Vec<_> = configs
        .iter()
        .rev()
        .flat_map(|&(label, mode, ciphersuite)| {
            GROUP_SIZES
                .iter()
                .map(move |&size| (label, mode, ciphersuite, size))
        })
        .collect();

    let total: u64 = tasks
        .iter()
        .map(|(_, _, _, s)| (s.saturating_sub(1) * s / 2) as u64)
        .sum();
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} (eta {eta}) {per_sec}",
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    let reports: Vec<SizeReport> = tasks
        .into_iter()
        .map(|(label, mode, ciphersuite, size)| measure(mode, ciphersuite, size, label, &pb))
        .collect();
    pb.finish_and_clear();

    // TABLE 1: Performance Summary
    println!("\n### TABLE 1: Summary (Bytes)\n");
    println!(
        "{:<45} {:>7} {:>10} {:>12} {:>10} {:>14} {:>12} {:>12}",
        "Ciphersuite", "Members", "KP", "Add", "Welc", "Upd", "Creator", "Member"
    );
    println!("{}", "-".repeat(129));

    for r in &reports {
        println!(
            "{:<45} {:>7} {:>10} {:>12} {:>10} {:>14} {:>12} {:>12}",
            r.label,
            commify(r.group_size),
            commify(r.key_package_bytes),
            commify(r.add_commit_bytes),
            commify(r.welcome_bytes),
            commify(r.update_commit_bytes),
            commify(r.creator_storage_bytes.full_db),
            commify(r.member_storage_bytes.full_db)
        );
    }

    // TABLE 2: Creator Storage Breakdown
    println!("\n### TABLE 2: Creator Storage Group Data Details (Bytes)\n");
    println!(
        "{:<45} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "Ciphersuite",
        "Members",
        "AppTree",
        "Conf",
        "Ctx",
        "Epoch",
        "State",
        "Trn",
        "Join",
        "Msg",
        "Leaf",
        "Res",
        "Tree"
    );
    println!("{}", "-".repeat(153));

    for r in &reports {
        let d = &r.creator_storage_bytes.group_data;
        println!(
            "{:<45} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            r.label,
            commify(r.group_size),
            commify(d.application_export_tree),
            commify(d.confirmation_tag),
            commify(d.context),
            commify(d.group_epoch_secrets),
            commify(d.group_state),
            commify(d.interim_transcript_hash),
            commify(d.join_group_config),
            commify(d.message_secrets),
            commify(d.own_leaf_index),
            commify(d.resumption_psk_store),
            commify(d.tree)
        );
    }
}
