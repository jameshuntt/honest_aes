//! Every mode against the RustCrypto implementation on random inputs, plus
//! the refusals and the fail-closed paths.

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::aead::{Aead, Payload};
use cmac::Mac;
use honest_aes::{cbc as hcbc, cmac as hcmac, ctr as hctr, gcm, Aes, AesError};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xA5A5)
}

fn bytes(rng: &mut ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

#[test]
fn block_cipher_agrees_with_rustcrypto_for_all_three_key_sizes() {
    let mut rng = rng();
    for _ in 0..64 {
        let mut block = [0u8; 16];
        rng.fill_bytes(&mut block);

        let key = bytes(&mut rng, 16);
        let mut ours = block;
        Aes::new(&key).unwrap().encrypt_block(&mut ours);
        let mut theirs = aes::Block::from(block);
        aes::Aes128::new_from_slice(&key).unwrap().encrypt_block(&mut theirs);
        assert_eq!(ours, theirs.as_slice());

        let key = bytes(&mut rng, 24);
        let mut ours = block;
        Aes::new(&key).unwrap().encrypt_block(&mut ours);
        let mut theirs = aes::Block::from(block);
        aes::Aes192::new_from_slice(&key).unwrap().encrypt_block(&mut theirs);
        assert_eq!(ours, theirs.as_slice());

        let key = bytes(&mut rng, 32);
        let aes = Aes::new(&key).unwrap();
        let mut ours = block;
        aes.encrypt_block(&mut ours);
        let mut theirs = aes::Block::from(block);
        aes::Aes256::new_from_slice(&key).unwrap().encrypt_block(&mut theirs);
        assert_eq!(ours, theirs.as_slice());
        aes.decrypt_block(&mut ours);
        assert_eq!(ours, block);
    }
}

#[test]
fn ctr_agrees_with_rustcrypto_including_counter_wrap() {
    let mut rng = rng();
    for len in [0usize, 1, 15, 16, 17, 100, 333] {
        let key = bytes(&mut rng, 32);
        let mut counter = [0xffu8; 16];
        counter[0] = 0x12; // wrap the low bytes early in the message
        let data = bytes(&mut rng, len);

        let mut ours = data.clone();
        hctr::apply(&Aes::new(&key).unwrap(), &counter, &mut ours);

        let mut theirs = data.clone();
        ::ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&key, &counter).unwrap().apply_keystream(&mut theirs);
        assert_eq!(ours, theirs, "len {len}");
    }
}

#[test]
fn cbc_agrees_with_rustcrypto_padding_included() {
    use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut};
    let mut rng = rng();
    for len in [0usize, 1, 15, 16, 17, 31, 32, 200] {
        let key = bytes(&mut rng, 16);
        let iv: [u8; 16] = bytes(&mut rng, 16).try_into().unwrap();
        let plaintext = bytes(&mut rng, len);
        let aes = Aes::new(&key).unwrap();

        let ours = hcbc::encrypt(&aes, &iv, &plaintext);
        let theirs = ::cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
        assert_eq!(ours, theirs, "len {len}");

        assert_eq!(hcbc::decrypt(&aes, &iv, &ours).unwrap(), plaintext);
        let back = ::cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(&ours)
            .unwrap();
        assert_eq!(back, plaintext);
    }
}

#[test]
fn cbc_refusals() {
    let aes = Aes::aes128(&[1; 16]);
    let iv = [0u8; 16];
    assert_eq!(hcbc::encrypt_blocks(&aes, &iv, &mut [0u8; 15]).unwrap_err(), AesError::NotBlockAligned(15));
    assert_eq!(hcbc::decrypt(&aes, &iv, &[]).unwrap_err(), AesError::NotBlockAligned(0));
    assert_eq!(hcbc::decrypt(&aes, &iv, &[0; 17]).unwrap_err(), AesError::NotBlockAligned(17));
    // a flipped ciphertext byte in the last block breaks the padding (almost always)
    let mut ct = hcbc::encrypt(&aes, &iv, b"a padded message of two blocks");
    let last = ct.len() - 1;
    ct[last - 16] ^= 0xff; // the byte that XORs into the padding byte on decrypt
    assert_eq!(hcbc::decrypt(&aes, &iv, &ct).unwrap_err(), AesError::InvalidPadding);
    // a wrong key too
    assert!(hcbc::decrypt(&Aes::aes128(&[2; 16]), &iv, &hcbc::encrypt(&aes, &iv, b"x")).is_err());
}

#[test]
fn cmac_agrees_with_rustcrypto() {
    let mut rng = rng();
    for len in [0usize, 1, 15, 16, 17, 32, 33, 100] {
        let key = bytes(&mut rng, 32);
        let msg = bytes(&mut rng, len);
        let ours = hcmac::tag(&Aes::new(&key).unwrap(), &msg);
        let mut theirs = <::cmac::Cmac<aes::Aes256> as KeyInit>::new_from_slice(&key).unwrap();
        theirs.update(&msg);
        assert_eq!(ours.as_slice(), theirs.finalize().into_bytes().as_slice(), "len {len}");
    }
}

#[test]
fn gcm_agrees_with_rustcrypto_and_fails_closed() {
    let mut rng = rng();
    for (len, aad_len) in [(0usize, 0usize), (1, 0), (16, 16), (17, 3), (100, 0), (257, 40)] {
        let key = bytes(&mut rng, 32);
        let nonce = bytes(&mut rng, 12);
        let aad = bytes(&mut rng, aad_len);
        let plaintext = bytes(&mut rng, len);
        let aes = Aes::new(&key).unwrap();

        let ours = gcm::encrypt(&aes, &nonce, &aad, &plaintext).unwrap();
        let theirs = aes_gcm::Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
            .unwrap();
        assert_eq!(ours, theirs, "len {len} aad {aad_len}");

        assert_eq!(gcm::decrypt(&aes, &nonce, &aad, &ours).unwrap(), plaintext);

        // one flipped bit anywhere: refused, and the in-place buffer is zeroized
        if !ours.is_empty() {
            let mut tampered = ours.clone();
            let i = (rng.next_u32() as usize) % tampered.len();
            tampered[i] ^= 0x01;
            assert_eq!(gcm::decrypt(&aes, &nonce, &aad, &tampered).unwrap_err(), AesError::TagMismatch);
            let (body, tag) = tampered.split_at(tampered.len() - 16);
            let mut buf = body.to_vec();
            assert!(gcm::open(&aes, &nonce, &aad, &mut buf, tag.try_into().unwrap()).is_err());
            assert!(buf.iter().all(|&b| b == 0), "buffer zeroized on mismatch");
        }
        // wrong AAD: refused
        assert!(gcm::decrypt(&aes, &nonce, b"other", &ours).is_err());
    }
}

#[test]
fn gcm_with_a_non_96_bit_nonce_agrees_with_rustcrypto() {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::AesGcm;
    type Aes128Gcm64 = AesGcm<aes::Aes128, aes_gcm::aead::consts::U8>;
    let mut rng = rng();
    let key = bytes(&mut rng, 16);
    let nonce = bytes(&mut rng, 8);
    let plaintext = bytes(&mut rng, 50);
    let ours = gcm::encrypt(&Aes::new(&key).unwrap(), &nonce, b"aad", &plaintext).unwrap();
    let theirs = Aes128Gcm64::new_from_slice(&key)
        .unwrap()
        .encrypt(GenericArray::from_slice(&nonce), Payload { msg: &plaintext, aad: b"aad" })
        .unwrap();
    assert_eq!(ours, theirs);
}

#[test]
fn refusals_and_debug() {
    assert_eq!(Aes::new(&[0; 15]).unwrap_err(), AesError::InvalidKeyLength(15));
    assert_eq!(AesError::InvalidKeyLength(15).to_string(), "AES keys are 16, 24 or 32 bytes, not 15");
    let aes = Aes::aes192(&[0; 24]);
    assert_eq!(aes.key_bits(), 192);
    assert_eq!(aes.rounds(), 12);
    assert_eq!(format!("{aes:?}"), "Aes-192([REDACTED])");
    assert_eq!(gcm::seal(&aes, &[], b"", &mut []).unwrap_err(), AesError::InvalidNonceLength(0));
    assert_eq!(gcm::decrypt(&aes, &[0; 12], b"", &[0; 15]).unwrap_err(), AesError::TagMismatch);
}
