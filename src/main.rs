// use std::{env, process};
use std::str::FromStr;
use std::io;

// rand crate recommend using ring for secure applications
use ring::rand::{SystemRandom,SecureRandom};
use bip39::Mnemonic;

use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::network::constants::Network;
use miniscript::bitcoin::util::bip32::{
    ExtendedPrivKey, ExtendedPubKey, DerivationPath
};
use miniscript::{
    DescriptorTrait, DescriptorPublicKey, TranslatePk2
};

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
    print!("{}\n", EraseLines(8));

    // we need secp256k1 context for key derivation
    let secp = Secp256k1::new();

    // generate seed and root key
    let seed = mnemonic.to_seed(&passwd);
    let network = Network::Bitcoin;
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
    let fingerprint = root.fingerprint(&secp);

    // derive child xpub
    let path = "m/84h/0h/0h";
    let derivation = DerivationPath::from_str(path).unwrap();
    let child = root.derive_priv(&secp, &derivation).unwrap();
    let xpub = ExtendedPubKey::from_private(&secp, &child);
    let keystr = format!("[{}{}]{}", fingerprint, &path[1..], xpub);
    println!("Child public key:\n{}\n", keystr);

    // Bitcoin Core descriptors
    let desc = miniscript::Descriptor::<DescriptorPublicKey>::from_str(
        &format!("wpkh({}/0/*)", keystr)
    ).unwrap();
    println!("Bitcoin Core descriptor:\n{}\n", desc);
    // First 5 addresses
    println!("First 3 addresses:");
    for idx in 0..3 {
        let addr = desc.derive(idx)
            .translate_pk2(|xpk| xpk.derive_public_key(&secp)).unwrap()
            .address(network).unwrap();
        println!("{}", addr);
    }

}
