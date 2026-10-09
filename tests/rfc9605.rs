//! Runs the test vectors of [RFC 9605 Appendix C](https://www.rfc-editor.org/rfc/rfc9605.html#appendix-C)
//! through the public frame API: the header encodings of C.1, and every SFrame encryption of C.3
//! whose cipher suite the crypto backend supports, encrypted and decrypted, as views and as owned
//! frames.
//!
//! The unit tests check the vectors below the frame API, against the AEAD with an AAD they build
//! themselves. This target checks what a caller gets, including the AAD the frame API builds from
//! the header and the meta data (RFC 9605 4.4.3).

#![cfg(crypto_backend)]

use pretty_assertions::assert_eq;
use serde::Deserialize;
use sframe::{
    CipherSuite,
    frame::{EncryptedFrame, EncryptedFrameView, MediaFrame, MediaFrameView, MonotonicCounter},
    header::SframeHeader,
    key::{DecryptionKey, EncryptionKey},
};

/// The same vectors the unit tests use, transcribed from RFC 9605 Appendix C
const TEST_VECTORS: &str = include_str!("../src/test_vectors/test-vectors.json");

#[derive(Deserialize)]
struct TestVectors {
    header: Vec<HeaderVector>,
    sframe: Vec<SframeVector>,
}

#[derive(Deserialize)]
struct HeaderVector {
    kid: u64,
    ctr: u64,
    #[serde(deserialize_with = "from_hex")]
    encoded: Vec<u8>,
}

#[derive(Deserialize)]
struct SframeVector {
    cipher_suite: u16,
    kid: u64,
    ctr: u64,
    #[serde(deserialize_with = "from_hex")]
    base_key: Vec<u8>,
    #[serde(deserialize_with = "from_hex")]
    metadata: Vec<u8>,
    #[serde(deserialize_with = "from_hex")]
    aad: Vec<u8>,
    #[serde(deserialize_with = "from_hex")]
    pt: Vec<u8>,
    #[serde(deserialize_with = "from_hex")]
    ct: Vec<u8>,
}

fn from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: &str = Deserialize::deserialize(deserializer)?;
    hex::decode(hex_str).map_err(serde::de::Error::custom)
}

fn test_vectors() -> TestVectors {
    serde_json::from_str(TEST_VECTORS).unwrap()
}

/// The cipher suite of a vector, if the crypto backend in use supports it
fn cipher_suite(id: u16) -> Option<CipherSuite> {
    match id {
        #[cfg(aes_ctr)]
        0x0001 => Some(CipherSuite::AesCtr128HmacSha256_80),
        #[cfg(aes_ctr)]
        0x0002 => Some(CipherSuite::AesCtr128HmacSha256_64),
        #[cfg(aes_ctr)]
        0x0003 => Some(CipherSuite::AesCtr128HmacSha256_32),
        0x0004 => Some(CipherSuite::AesGcm128Sha256),
        0x0005 => Some(CipherSuite::AesGcm256Sha512),
        _ => None,
    }
}

fn header_bytes(header: &SframeHeader) -> Vec<u8> {
    let mut buffer = vec![0u8; header.len()];
    header.serialize(&mut buffer).unwrap();
    buffer
}

#[test]
fn header_vectors_of_c1() {
    let vectors = test_vectors().header;
    assert_eq!(vectors.len(), 289);

    for vector in &vectors {
        let header = SframeHeader::new(vector.kid, vector.ctr);
        assert_eq!(header_bytes(&header), vector.encoded);

        let decoded = SframeHeader::deserialize(&vector.encoded).unwrap();
        assert_eq!(decoded.key_id(), vector.kid);
        assert_eq!(decoded.counter(), vector.ctr);
    }
}

#[test]
fn every_vector_of_c3_carries_meta_data_after_the_header_in_its_aad() {
    for vector in test_vectors().sframe {
        assert!(!vector.metadata.is_empty());
        let header = SframeHeader::deserialize(&vector.ct).unwrap();
        assert_eq!(
            vector.aad,
            [header_bytes(&header), vector.metadata.clone()].concat()
        );
    }
}

/// Runs a check on every C.3 vector of a cipher suite the backend supports, and makes sure the
/// GCM suites, which every backend supports, are among them
fn for_each_supported_c3_vector(check: impl Fn(CipherSuite, &SframeVector)) {
    let mut tested = Vec::new();
    for vector in test_vectors().sframe {
        let Some(cipher_suite) = cipher_suite(vector.cipher_suite) else {
            continue;
        };
        check(cipher_suite, &vector);
        tested.push(vector.cipher_suite);
    }

    assert!(tested.contains(&0x0004));
    assert!(tested.contains(&0x0005));
    #[cfg(aes_ctr)]
    assert_eq!(tested, [0x0001, 0x0002, 0x0003, 0x0004, 0x0005]);
}

#[test]
fn encrypt_c3_vectors_as_view() {
    for_each_supported_c3_vector(|cipher_suite, vector| {
        let key = EncryptionKey::derive_from(cipher_suite, vector.kid, &vector.base_key).unwrap();
        let mut counter = MonotonicCounter::with_start_value(vector.ctr, u64::MAX);
        let media_frame =
            MediaFrameView::try_with_meta_data(&mut counter, &vector.pt, &vector.metadata).unwrap();
        let mut buffer = Vec::new();

        let encrypted_frame = media_frame.encrypt_into(&key, &mut buffer).unwrap();

        let sframe = [
            header_bytes(encrypted_frame.header()),
            encrypted_frame.cipher_text().to_vec(),
        ]
        .concat();
        assert_eq!(sframe, vector.ct, "cipher suite {cipher_suite}");
        assert_eq!(encrypted_frame.meta_data(), vector.metadata);
        assert_eq!(
            buffer,
            [vector.metadata.clone(), vector.ct.clone()].concat()
        );
    });
}

#[test]
fn encrypt_c3_vectors_as_owned_frame() {
    for_each_supported_c3_vector(|cipher_suite, vector| {
        let key = EncryptionKey::derive_from(cipher_suite, vector.kid, &vector.base_key).unwrap();
        let mut counter = MonotonicCounter::with_start_value(vector.ctr, u64::MAX);
        let media_frame =
            MediaFrame::try_with_meta_data(&mut counter, &vector.pt, &vector.metadata).unwrap();

        let encrypted_frame = media_frame.encrypt(&key).unwrap();

        let meta_len = vector.metadata.len();
        assert_eq!(
            &encrypted_frame.as_ref()[meta_len..],
            vector.ct,
            "cipher suite {cipher_suite}"
        );
        assert_eq!(encrypted_frame.meta_data(), vector.metadata);
    });
}

#[test]
fn decrypt_c3_vectors_as_view() {
    for_each_supported_c3_vector(|cipher_suite, vector| {
        let key = DecryptionKey::derive_from(cipher_suite, vector.kid, &vector.base_key).unwrap();
        let encrypted_frame =
            EncryptedFrameView::try_with_meta_data(&vector.ct, &vector.metadata).unwrap();
        let mut buffer = Vec::new();

        let media_frame = encrypted_frame
            .decrypt_into(&key, &mut buffer)
            .unwrap_or_else(|err| panic!("cipher suite {cipher_suite}: {err}"));

        assert_eq!(media_frame.payload(), vector.pt);
        assert_eq!(media_frame.meta_data(), vector.metadata);
        assert_eq!(media_frame.counter(), vector.ctr);
    });
}

#[test]
fn decrypt_c3_vectors_as_owned_frame() {
    for_each_supported_c3_vector(|cipher_suite, vector| {
        let key = DecryptionKey::derive_from(cipher_suite, vector.kid, &vector.base_key).unwrap();
        let encrypted_frame =
            EncryptedFrame::try_with_meta_data(&vector.ct, &vector.metadata).unwrap();

        let media_frame = encrypted_frame
            .decrypt(&key)
            .unwrap_or_else(|err| panic!("cipher suite {cipher_suite}: {err}"));

        assert_eq!(media_frame.payload(), vector.pt);
        assert_eq!(media_frame.meta_data(), vector.metadata);
        assert_eq!(media_frame.counter(), vector.ctr);
    });
}

#[test]
fn c3_vectors_reject_meta_data_other_than_their_own() {
    for_each_supported_c3_vector(|cipher_suite, vector| {
        let key = DecryptionKey::derive_from(cipher_suite, vector.kid, &vector.base_key).unwrap();
        let mut other_meta_data = vector.metadata.clone();
        other_meta_data[0] ^= 0x01;
        let encrypted_frame =
            EncryptedFrameView::try_with_meta_data(&vector.ct, &other_meta_data).unwrap();

        assert!(encrypted_frame.decrypt(&key).is_err());
    });
}
