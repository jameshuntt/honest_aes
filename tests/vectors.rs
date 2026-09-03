//! Known answers from the standards: FIPS 197 Appendix C, SP 800-38A
//! Appendix F, RFC 4493, and the GCM specification's test cases.

use honest_aes::{cbc, cmac, ctr, gcm, Aes};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s.replace(' ', "")).unwrap()
}

fn block(s: &str) -> [u8; 16] {
    h(s).try_into().unwrap()
}

#[test]
fn fips_197_appendix_c_single_blocks() {
    let plaintext = block("00112233445566778899aabbccddeeff");
    let cases = [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
    ];
    for (key, expected) in cases {
        let aes = Aes::new(&h(key)).unwrap();
        assert_eq!(aes.key_bits(), key.len() * 4);
        let mut b = plaintext;
        aes.encrypt_block(&mut b);
        assert_eq!(b, block(expected), "AES-{}", key.len() * 4);
        aes.decrypt_block(&mut b);
        assert_eq!(b, plaintext);
    }
}

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710";

#[test]
fn sp_800_38a_f1_ecb() {
    let aes = Aes::aes128(&block(KEY_128));
    let mut data = h(PLAINTEXT);
    for chunk in data.chunks_exact_mut(16) {
        aes.encrypt_block(chunk.try_into().unwrap());
    }
    assert_eq!(data, h("3ad77bb40d7a3660a89ecaf32466ef97 f5d3d58503b9699de785895a96fdbaaf 43b1cd7f598ece23881b00e3ed030688 7b0c785e27e8ad3f8223207104725dd4"));

    let aes = Aes::aes256(&h(KEY_256).try_into().unwrap());
    let mut data = h(PLAINTEXT);
    for chunk in data.chunks_exact_mut(16) {
        aes.encrypt_block(chunk.try_into().unwrap());
    }
    assert_eq!(data, h("f3eed1bdb5d2a03c064b5a7e3db181f8 591ccb10d410ed26dc5ba74a31362870 b6ed21b99ca6f4f9f153e7b1beafed1d 23304b7a39f9f3ff067d8d8f9e24ecc7"));
}

#[test]
fn sp_800_38a_f2_cbc() {
    let iv = block("000102030405060708090a0b0c0d0e0f");
    let aes = Aes::aes128(&block(KEY_128));
    let mut data = h(PLAINTEXT);
    cbc::encrypt_blocks(&aes, &iv, &mut data).unwrap();
    assert_eq!(data, h("7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2 73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7"));
    cbc::decrypt_blocks(&aes, &iv, &mut data).unwrap();
    assert_eq!(data, h(PLAINTEXT));

    let aes = Aes::aes256(&h(KEY_256).try_into().unwrap());
    let mut data = h(PLAINTEXT);
    cbc::encrypt_blocks(&aes, &iv, &mut data).unwrap();
    assert_eq!(data, h("f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d 39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b"));
}

#[test]
fn sp_800_38a_f5_ctr() {
    let counter = block("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let aes = Aes::aes128(&block(KEY_128));
    let mut data = h(PLAINTEXT);
    ctr::apply(&aes, &counter, &mut data);
    assert_eq!(data, h("874d6191b620e3261bef6864990db6ce 9806f66b7970fdff8617187bb9fffdff 5ae4df3edbd5d35e5b4f09020db03eab 1e031dda2fbe03d1792170a0f3009cee"));

    let aes = Aes::aes256(&h(KEY_256).try_into().unwrap());
    let mut data = h(PLAINTEXT);
    ctr::apply(&aes, &counter, &mut data);
    assert_eq!(data, h("601ec313775789a5b7a7f504bbf3d228 f443e3ca4d62b59aca84e990cacaf5c5 2b0930daa23de94ce87017ba2d84988d dfc9c58db67aada613c2dd08457941a6"));
}

#[test]
fn rfc_4493_cmac_examples() {
    let aes = Aes::aes128(&block(KEY_128));
    let msg = h(PLAINTEXT);
    let cases: [(usize, &str); 4] = [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ];
    for (len, expected) in cases {
        assert_eq!(cmac::tag(&aes, &msg[..len]), block(expected), "len {len}");
        assert!(cmac::verify(&aes, &msg[..len], &block(expected)));
    }
    let mut wrong = block(cases[1].1);
    wrong[0] ^= 1;
    assert!(!cmac::verify(&aes, &msg[..16], &wrong));
}

#[test]
fn gcm_spec_test_cases_1_to_4() {
    // test case 1: K = 0, P = {}, IV = 0^96
    let aes = Aes::aes128(&[0; 16]);
    let mut empty: [u8; 0] = [];
    let tag = gcm::seal(&aes, &[0; 12], b"", &mut empty).unwrap();
    assert_eq!(tag, block("58e2fccefa7e3061367f1d57a4e7455a"));

    // test case 2: P = 0^128
    let mut data = [0u8; 16];
    let tag = gcm::seal(&aes, &[0; 12], b"", &mut data).unwrap();
    assert_eq!(data, block("0388dace60b6a392f328c2b971b2fe78"));
    assert_eq!(tag, block("ab6e47d42cec13bdf53a67b21257bddf"));
    gcm::open(&aes, &[0; 12], b"", &mut data, &tag).unwrap();
    assert_eq!(data, [0; 16]);

    // test case 3: a real key, 64 bytes of plaintext, no AAD
    let aes = Aes::aes128(&block("feffe9928665731c6d6a8f9467308308"));
    let iv = h("cafebabefacedbaddecaf888");
    let plaintext = h("d9313225f88406e5a55909c5aff5269a 86a7a9531534f7da2e4c303d8a318a72 1c3c0c95956809532fcf0e2449a6b525 b16aedf5aa0de657ba637b391aafd255");
    let mut data = plaintext.clone();
    let tag = gcm::seal(&aes, &iv, b"", &mut data).unwrap();
    assert_eq!(data, h("42831ec2217774244b7221b784d0d49c e3aa212f2c02a4e035c17e2329aca12e 21d514b25466931c7d8f6a5aac84aa05 1ba30b396a0aac973d58e091473f5985"));
    assert_eq!(tag, block("4d5c2af327cd64a62cf35abd2ba6fab4"));

    // test case 4: the same, 60 bytes of plaintext and 20 bytes of AAD
    let aad = h("feedfacedeadbeeffeedfacedeadbeef abaddad2");
    let mut data = plaintext[..60].to_vec();
    let tag = gcm::seal(&aes, &iv, &aad, &mut data).unwrap();
    assert_eq!(tag, block("5bc94fbc3221a5db94fae95ae7121a47"));
    gcm::open(&aes, &iv, &aad, &mut data, &tag).unwrap();
    assert_eq!(data, plaintext[..60]);
}

#[test]
fn gcm_spec_test_case_5_uses_a_short_nonce() {
    // test case 5: IV = cafebabefacedbad (64 bits), so J0 comes from GHASH
    let aes = Aes::aes128(&block("feffe9928665731c6d6a8f9467308308"));
    let iv = h("cafebabefacedbad");
    let aad = h("feedfacedeadbeeffeedfacedeadbeef abaddad2");
    let plaintext = h("d9313225f88406e5a55909c5aff5269a 86a7a9531534f7da2e4c303d8a318a72 1c3c0c95956809532fcf0e2449a6b525 b16aedf5aa0de657ba637b39");
    let mut data = plaintext.clone();
    let tag = gcm::seal(&aes, &iv, &aad, &mut data).unwrap();
    assert_eq!(data, h("61353b4c2806934a777ff51fa22a4755 699b2a714fcdc6f83766e5f97b6c7423 73806900e49f24b22b097544d4896b42 4989b5e1ebac0f07c23f4598"));
    assert_eq!(tag, block("3612d2e79e3b0785561be14aaca2fccb"));
}
