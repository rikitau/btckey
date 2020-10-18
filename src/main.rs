// use std::{env, process};
use std::str::FromStr;
use std::io;

// rand crate recommend using ring for secure applications
use ring::rand::{SystemRandom,SecureRandom};
use bip39::Mnemonic;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::util::bip32::DerivationPath;

use ansi_escapes::EraseLines;

fn main() {
    let rng = SystemRandom::new();
    let mut entropy = vec![0u8; 16];
    rng.fill(&mut entropy).unwrap();
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    println!("Here is your mnemonic:\n\n{}\n", mnemonic);
    println!("Write it down and enter your BIP39 password, or just hit ENTER.");
    println!("WARNING: mnemonic will be erased from the screen!");
    let mut passwd = String::new();
    io::stdin().read_line(&mut passwd).unwrap();
    // remove trailing \n
    passwd.truncate(passwd.len() - 1);
    // delete mnemonic phrase, will work even if term window is small
    // and mnemonic is displayed on two lines
    print!("{}", EraseLines(8));

    // generate seed and root key
    let seed = mnemonic.to_seed(&passwd);
    let network = Network::Bitcoin;
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();

    // we need secp256k1 context for key derivation
    let secp = Secp256k1::new();

    // derive child xpub
    // TODO: calculate fingerprint and display in Core-like format:
    // [fingerprint/derivation]xpub
    let path = DerivationPath::from_str("m/44h/0h/0h").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let xpub = ExtendedPubKey::from_private(&secp, &child);
    println!("Child public key at {}: {}", path, xpub);

    // TODO: derive keys for different purposes and construct
    // Bitcoin Core descriptors
}
