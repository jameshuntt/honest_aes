//! Seal a data key under a wrapping key with AES-256-GCM, then open it.
//!
//! cargo run --example seal

use honest_aes::{gcm, Aes};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let wrapping_key = Aes::aes256(&[0x4b; 32]);
    let nonce = [0x01u8; 12]; // one per message under this key, never repeated
    let data_key = [0xd4u8; 32];

    let sealed = gcm::encrypt(&wrapping_key, &nonce, b"data-key:v1", &data_key).expect("nonce present");
    println!("sealed ({} bytes): {}", sealed.len(), hex(&sealed));

    let opened = gcm::decrypt(&wrapping_key, &nonce, b"data-key:v1", &sealed).expect("tag matches");
    println!("opened matches: {}", opened == data_key);

    let refused = gcm::decrypt(&wrapping_key, &nonce, b"data-key:v2", &sealed);
    println!("with the wrong header: {refused:?}");
}
