// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Measures message sizes and CBOR-encoded storage size of APQ MLS group state
//! across ciphersuites and group sizes.
//!
//! Run with: `cargo run --example sizes`

use apqmls::{
    ApqCiphersuite, ApqMlsGroup,
    authentication::{ApqCredentialWithKey, ApqSignatureKeyPair},
    extension::PqtMode,
    messages::{ApqKeyPackage, ApqMlsMessageIn, ApqMlsMessageOut},
};
use openmls::{
    group::MlsGroupJoinConfig,
    prelude::{Ciphersuite, Credential, OpenMlsProvider},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

const GROUP_SIZES: &[usize] = &[2, 10];
const EPOCHS: usize = 10;

struct Member {
    provider: OpenMlsRustCrypto,
    group: ApqMlsGroup,
}

/// Returns the CBOR-encoded size of all key-value pairs in the provider's storage.
fn cbor_storage_size(provider: &OpenMlsRustCrypto) -> usize {
    let values = provider.storage().values.read().unwrap();
    let mut buf = Vec::new();
    ciborium::into_writer(&*values, &mut buf).unwrap();
    buf.len()
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
    creator_storage_bytes: usize,
    member_storage_bytes: usize,
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

fn measure(
    mode: PqtMode,
    ciphersuite: ApqCiphersuite,
    group_size: usize,
    label: &'static str,
) -> SizeReport {
    let (creator_provider, creator_signer, creator_cred) = new_client("alice", ciphersuite);
    let mut creator_group = ApqMlsGroup::builder()
        .set_mode(mode)
        .with_ciphersuite(ciphersuite)
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

    // Run EPOCHS self-update epochs and track average commit size.
    let mut update_commit_total = 0usize;
    for _ in 0..EPOCHS {
        let bundle = creator_group
            .commit_builder()
            .force_self_update(true)
            .finalize(&creator_provider, &creator_signer, |_| true, |_| true)
            .unwrap();
        creator_group
            .merge_pending_commit(&creator_provider)
            .unwrap();

        update_commit_total += bundle.commit.tls_serialize_detached().unwrap().len();
        let commit_for_members = bundle.commit.clone();
        for m in &mut members {
            process_commit_on_member(m, &commit_for_members);
        }
    }

    let creator_storage_bytes = cbor_storage_size(&creator_provider);
    let member_storage_bytes = if members.is_empty() {
        0
    } else {
        members
            .iter()
            .map(|m| cbor_storage_size(&m.provider))
            .sum::<usize>()
            / members.len()
    };

    SizeReport {
        label,
        group_size,
        key_package_bytes: last_kp_bytes,
        add_commit_bytes: last_add_commit_bytes,
        welcome_bytes: last_welcome_bytes,
        update_commit_bytes: update_commit_total / EPOCHS,
        creator_storage_bytes,
        member_storage_bytes,
    }
}

fn main() {
    const T_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
    // Note: TBD1 is not interesting with AES-GCM128
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

    println!(
        "{:<45} {:>7} {:>10} {:>12} {:>10} {:>14} {:>16} {:>14}",
        "Ciphersuite",
        "Members",
        "KP (B)",
        "AddCommit (B)",
        "Welcome (B)",
        "UpdCommit (B)",
        "CreatorStore (B)",
        "MemberStore (B)",
    );
    println!("{}", "-".repeat(132));

    for &(label, mode, ciphersuite) in configs {
        for &size in GROUP_SIZES {
            let r = measure(mode, ciphersuite, size, label);
            println!(
                "{:<45} {:>7} {:>10} {:>12} {:>10} {:>14} {:>16} {:>14}",
                r.label,
                commify(r.group_size),
                commify(r.key_package_bytes),
                commify(r.add_commit_bytes),
                commify(r.welcome_bytes),
                commify(r.update_commit_bytes),
                commify(r.creator_storage_bytes),
                commify(r.member_storage_bytes),
            );
        }
        println!();
    }
}
