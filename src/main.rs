// use std::{env, process};
use std::str::FromStr;

// rand crate recommend using ring for secure applications
use ring::rand::{SystemRandom,SecureRandom};
use bip39::Mnemonic;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::util::bip32::DerivationPath;

fn main() {
    let rng = SystemRandom::new();
    let mut entropy = vec![0u8; 16];
    rng.fill(&mut entropy).unwrap();
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    println!("Here is your mnemonic:\n{}", mnemonic);
    // empty password for now
    let seed = mnemonic.to_seed("");
    let network = Network::Bitcoin;
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
    println!("Root key: {}", root);

    // we need secp256k1 context for key derivation
    let secp = Secp256k1::new();

    // derive child xpub
    let path = DerivationPath::from_str("m/84h/0h/0h").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    println!("Child at {}: {}", path, child);
    let xpub = ExtendedPubKey::from_private(&secp, &child);
    println!("Public key at {}: {}", path, xpub);
}
