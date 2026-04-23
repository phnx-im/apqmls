// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Measures serialized sizes (bytes) of APQ MLS group messages across
//! ciphersuites and group sizes.
//!
//! Run with: `cargo run --example sizes`

use apqmls::{
    ApqCiphersuite, ApqMlsGroup,
    authentication::{ApqCredentialWithKey, ApqSignatureKeyPair},
    extension::PqtMode,
    messages::{ApqKeyPackage, ApqMlsMessageIn, ApqMlsMessageOut},
};
use openmls::{group::MlsGroupJoinConfig, prelude::Credential};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

const GROUP_SIZES: &[usize] = &[2, 10];
const EPOCHS: usize = 10;

struct Member {
    provider: OpenMlsRustCrypto,
    group: ApqMlsGroup,
}

struct SizeReport {
    ciphersuite_label: &'static str,
    group_size: usize,
    key_package_bytes: usize,
    add_commit_bytes: usize,
    welcome_bytes: usize,
    update_commit_bytes: [usize; EPOCHS],
}

impl SizeReport {
    fn avg_update_commit(&self) -> usize {
        self.update_commit_bytes.iter().sum::<usize>() / EPOCHS
    }
}

fn new_client(
    name: &str,
    ciphersuite: ApqCiphersuite,
) -> (OpenMlsRustCrypto, ApqSignatureKeyPair, ApqCredentialWithKey) {
    let provider = OpenMlsRustCrypto::default();
    let signer = ApqSignatureKeyPair::new(ciphersuite.into()).unwrap();
    let credential_with_key = ApqCredentialWithKey::new(name.as_bytes(), &signer);
    (provider, signer, credential_with_key)
}

fn process_commit_on_member(member: &mut Member, commit: &ApqMlsMessageOut) {
    let msg_in = ApqMlsMessageIn::try_from(commit.clone()).unwrap();
    let protocol_msg = msg_in.into_protocol_message().unwrap();
    let processed = member
        .group
        .process_message(
            &member.provider,
            protocol_msg,
            |c1: &Credential, c2: &Credential| c1 == c2,
        )
        .unwrap();
    member
        .group
        .merge_staged_commit(&member.provider, processed.into_staged_commit().unwrap())
        .unwrap();
}

fn measure(mode: PqtMode, group_size: usize, ciphersuite_label: &'static str) -> SizeReport {
    let ciphersuite = mode.default_ciphersuite();

    let (creator_provider, creator_signer, creator_cred) = new_client("alice", ciphersuite);
    let mut creator_group = ApqMlsGroup::builder()
        .set_mode(mode)
        .build(&creator_provider, &creator_signer, creator_cred)
        .unwrap();

    let mut members: Vec<Member> = vec![];
    let mut last_kp_bytes = 0usize;
    let mut last_add_commit_bytes = 0usize;
    let mut last_welcome_bytes = 0usize;

    for i in 1..group_size {
        let (member_provider, member_signer, member_cred) =
            new_client(&format!("member_{i}"), ciphersuite);

        let kp = ApqKeyPackage::builder()
            .build(&member_provider, ciphersuite, &member_signer, member_cred)
            .unwrap()
            .into_key_package();

        last_kp_bytes = ApqMlsMessageOut::from(kp.clone())
            .tls_serialize_detached()
            .unwrap()
            .len();

        let bundle = creator_group
            .commit_builder()
            .propose_adds([kp])
            .finalize(&creator_provider, &creator_signer, |_| true, |_| true)
            .unwrap();
        creator_group
            .merge_pending_commit(&creator_provider)
            .unwrap();

        last_add_commit_bytes = bundle.commit.tls_serialize_detached().unwrap().len();
        let commit_for_members = bundle.commit.clone();

        // Serialize welcome to measure wire size, then deserialize for joining.
        let welcome_out = ApqMlsMessageOut::from(bundle.welcome.unwrap());
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();
        last_welcome_bytes = welcome_bytes.len();

        let welcome = ApqMlsMessageIn::tls_deserialize_exact(&welcome_bytes[..])
            .unwrap()
            .into_welcome()
            .unwrap();

        let ratchet_tree = creator_group.export_ratchet_tree();
        let member_group = ApqMlsGroup::new_from_welcome(
            &member_provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(ratchet_tree.into()),
        )
        .unwrap();

        for m in &mut members {
            process_commit_on_member(m, &commit_for_members);
        }

        members.push(Member {
            provider: member_provider,
            group: member_group,
        });
    }

    // Run EPOCHS self-update epochs (creator updates, all members process).
    let mut update_commit_bytes = [0usize; EPOCHS];
    for epoch_bytes in &mut update_commit_bytes {
        let bundle = creator_group
            .commit_builder()
            .force_self_update(true)
            .finalize(&creator_provider, &creator_signer, |_| true, |_| true)
            .unwrap();
        creator_group
            .merge_pending_commit(&creator_provider)
            .unwrap();

        *epoch_bytes = bundle.commit.tls_serialize_detached().unwrap().len();
        let commit_for_members = bundle.commit.clone();

        for m in &mut members {
            process_commit_on_member(m, &commit_for_members);
        }
    }

    SizeReport {
        ciphersuite_label,
        group_size,
        key_package_bytes: last_kp_bytes,
        add_commit_bytes: last_add_commit_bytes,
        welcome_bytes: last_welcome_bytes,
        update_commit_bytes,
    }
}

fn main() {
    let configs: &[(PqtMode, &'static str)] = &[
        (PqtMode::ConfOnly, "ConfOnly"),
        (PqtMode::ConfAndAuth, "ConfAndAuth"),
    ];

    println!(
        "{:<14} {:>7} {:>12} {:>12} {:>10} {:>18}",
        "Ciphersuite", "Members", "KeyPkg (B)", "AddCommit (B)", "Welcome (B)", "UpdateCommit (B)"
    );
    println!("{}", "-".repeat(79));

    for &(mode, label) in configs {
        for &size in GROUP_SIZES {
            eprint!("  {label} / {size} members ...");
            let r = measure(mode, size, label);
            eprintln!(" done");
            println!(
                "{:<14} {:>7} {:>12} {:>12} {:>10} {:>18}",
                r.ciphersuite_label,
                r.group_size,
                r.key_package_bytes,
                r.add_commit_bytes,
                r.welcome_bytes,
                r.avg_update_commit(),
            );
        }
        println!();
    }
}
