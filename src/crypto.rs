//! XChaCha20-Poly1305 sealing for the supervisor's at-rest copies.
//!
//! `--encrypt-memory` keeps the real argv, environment and secret
//! material as ciphertext while the supervisor is at rest.  The key is a
//! [`SecBuf`], so it is locked against swap, excluded from core dumps and
//! backed by `memfd_secret` when the kernel offers it.  The ciphertext is
//! a normal allocation: it is safe to leave in the heap because it is
//! unreadable without the key.
//!
//! This module does not encrypt the payload's own heap or stack.  It
//! protects the supervisor's saved copies and the staging buffers; the
//! payload's redaction block is handled by `execimg` (anonymous and
//! `MADV_DONTDUMP`; a `memfd_secret` VMA would be a tool fingerprint).

use crate::mem::SecBuf;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::io;
use zeroize::Zeroizing;

/// A per-session 256-bit key in locked memory.
pub struct SessionKey {
    buf: SecBuf,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

impl SessionKey {
    /// Generate a fresh key from the kernel's random source.
    pub fn generate() -> io::Result<SessionKey> {
        // `Zeroizing` wipes the stack copy on every return path, including
        // the allocation failure in `SecBuf::from_slice`.
        let mut bytes = Zeroizing::new([0u8; 32]);
        random_bytes(&mut bytes[..])?;
        let buf = SecBuf::from_slice(&bytes[..])?;
        Ok(SessionKey { buf })
    }

    /// The key bytes.  Callers must not copy them into an unlocked buffer.
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// True when the key lives in a `memfd_secret` mapping.
    pub fn is_secret_mem(&self) -> bool {
        self.buf.is_secret_mem()
    }

    /// True when the key's pages are locked against swap.
    pub fn is_locked(&self) -> bool {
        self.buf.is_locked()
    }
}

/// One sealed buffer: a random 24-byte nonce and the ciphertext with its
/// authentication tag.
pub struct EncryptedBuf {
    nonce: [u8; 24],
    ct: Vec<u8>,
}

impl std::fmt::Debug for EncryptedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedBuf")
            .field("nonce", &"<redacted>")
            .field("len", &self.ct.len())
            .finish()
    }
}

impl EncryptedBuf {
    /// Seal `plaintext` under `key`, binding `aad` as associated data.
    #[allow(deprecated)]
    pub fn seal(key: &SessionKey, plaintext: &[u8], aad: &[u8]) -> io::Result<EncryptedBuf> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let mut nonce = [0u8; 24];
        random_bytes(&mut nonce)?;
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| io::Error::other("XChaCha20-Poly1305 seal failed"))?;
        Ok(EncryptedBuf { nonce, ct })
    }

    /// Open the buffer into locked memory.  A wrong key or a changed
    /// ciphertext fails the tag check.
    #[allow(deprecated)]
    pub fn open(&self, key: &SessionKey, aad: &[u8]) -> io::Result<SecBuf> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload { msg: &self.ct, aad },
                )
                .map_err(|_| io::Error::other("XChaCha20-Poly1305 open failed"))?,
        );
        let buf = SecBuf::from_slice(&plain[..])?;
        Ok(buf)
    }

    /// The ciphertext length (plaintext plus the 16-byte tag).
    pub fn len(&self) -> usize {
        self.ct.len()
    }

    /// True when the buffer holds no plaintext.
    pub fn is_empty(&self) -> bool {
        self.ct.is_empty()
    }
}

/// A sealed argv/envp vector.
pub struct EncryptedStrings {
    inner: EncryptedBuf,
}

impl std::fmt::Debug for EncryptedStrings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedStrings")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl EncryptedStrings {
    /// Serialize and seal a string vector.
    ///
    /// The wire form is a 4-byte little-endian count followed by each
    /// string as a 4-byte length and its bytes.  The count and the
    /// lengths are authenticated by the AEAD tag.
    pub fn seal(key: &SessionKey, strings: &[Vec<u8>]) -> io::Result<EncryptedStrings> {
        let mut plain = Zeroizing::new(Vec::new());
        plain.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        for s in strings {
            plain.extend_from_slice(&(s.len() as u32).to_le_bytes());
            plain.extend_from_slice(s);
        }
        let inner = EncryptedBuf::seal(key, &plain[..], b"pmask strings v1")?;
        Ok(EncryptedStrings { inner })
    }

    /// Open and parse the vector.  The caller must zeroize the result
    /// after the redaction block has been written.
    pub fn open(&self, key: &SessionKey) -> io::Result<Vec<Vec<u8>>> {
        let plain = self.inner.open(key, b"pmask strings v1")?;
        let bytes = plain.as_slice();
        // Every parsed string is plaintext.  A malformed vector returns
        // through `?`, so the guard must own the vector to wipe it.
        let mut out: Zeroizing<Vec<Vec<u8>>> = Zeroizing::new(Vec::new());
        let mut off = 0usize;
        let count = read_u32(bytes, &mut off)? as usize;
        if count > 1_000_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sealed string count is implausible",
            ));
        }
        out.reserve(count);
        for _ in 0..count {
            let len = read_u32(bytes, &mut off)? as usize;
            if off + len > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sealed string length runs past the buffer",
                ));
            }
            out.push(bytes[off..off + len].to_vec());
            off += len;
        }
        if off != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes after the sealed string vector",
            ));
        }
        Ok(std::mem::take(&mut *out))
    }
}

fn read_u32(buf: &[u8], off: &mut usize) -> io::Result<u32> {
    if *off + 4 > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sealed string header is truncated",
        ));
    }
    let v = u32::from_le_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off += 4;
    Ok(v)
}

fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        // SAFETY: writing into our own buffer.
        let n = unsafe {
            libc::getrandom(
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
                0,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SessionKey::generate().unwrap();
        let buf = EncryptedBuf::seal(&key, b"the real argv", b"aad").unwrap();
        let plain = buf.open(&key, b"aad").unwrap();
        assert_eq!(plain.as_slice(), b"the real argv");
    }

    #[test]
    fn ciphertext_has_no_canary() {
        let key = SessionKey::generate().unwrap();
        let buf = EncryptedBuf::seal(&key, b"CANARY-123", b"").unwrap();
        let debug = format!("{:?}", buf);
        assert!(!debug.contains("CANARY"));
    }

    #[test]
    fn wrong_key_fails() {
        let key = SessionKey::generate().unwrap();
        let other = SessionKey::generate().unwrap();
        let buf = EncryptedBuf::seal(&key, b"secret", b"").unwrap();
        assert!(buf.open(&other, b"").is_err());
    }

    #[test]
    fn strings_roundtrip() {
        let key = SessionKey::generate().unwrap();
        let v = vec![b"one".to_vec(), b"two".to_vec(), Vec::new()];
        let sealed = EncryptedStrings::seal(&key, &v).unwrap();
        assert_eq!(sealed.open(&key).unwrap(), v);
    }
}
