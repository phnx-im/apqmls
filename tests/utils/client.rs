// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::{
    HpqCiphersuite,
    authentication::{HpqCredentialWithKey, HpqSignatureKeyPair, HpqSignatureScheme},
    messages::HpqKeyPackage,
};
use openmls::storage::OpenMlsProvider;

pub struct Client<Provider> {
    pub signer: HpqSignatureKeyPair,
    pub credential_with_key: HpqCredentialWithKey,
    pub provider: Provider,
}

impl<Provider: OpenMlsProvider> Client<Provider> {
    pub fn new(identity: &str, signature_scheme: HpqSignatureScheme, provider: Provider) -> Self {
        let keypair = HpqSignatureKeyPair::new(signature_scheme).unwrap();
        let credential_with_key = HpqCredentialWithKey::new(identity.as_bytes(), &keypair);

        Client {
            signer: keypair,
            credential_with_key,
            provider,
        }
    }

    pub fn generate_key_package(&self, ciphersuite: HpqCiphersuite) -> HpqKeyPackage {
        HpqKeyPackage::builder()
            .build(
                &self.provider,
                ciphersuite,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .unwrap()
            .into_key_package()
    }
}
