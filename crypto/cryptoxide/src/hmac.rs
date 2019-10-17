// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * This module implements the Hmac function - a Message Authentication Code using a Digest.
 */

use std::iter::repeat;

use cryptoutil;
use digest::Digest;
use mac::{Mac, MacResult};

/**
 * The Hmac struct represents an Hmac function - a Message Authentication Code using a Digest.
 */
pub struct Hmac<D> {
    digest: D,
    i_key: Vec<u8>,
    o_key: Vec<u8>,
    finished: bool
}

fn derive_key(key: &mut [u8], mask: u8) {
    for elem in key.iter_mut() {
        *elem ^= mask;
    }
}

// The key that Hmac processes must be the same as the block size of the underlying Digest. If the
// provided key is smaller than that, we just pad it with zeros. If its larger, we hash it and then
// pad it with zeros.
fn expand_key<D: Digest>(digest: &mut D, key: &[u8]) -> Vec<u8> {
    let bs = digest.block_size();
    let mut expanded_key: Vec<u8> = repeat(0).take(bs).collect();

    if key.len() <= bs {
        cryptoutil::copy_memory(key, &mut expanded_key);
    } else {
        let output_size = digest.output_bytes();
        digest.input(key);
        digest.result(&mut expanded_key[..output_size]);
        digest.reset();
    }
    expanded_key
}

// Hmac uses two keys derived from the provided key - one by xoring every byte with 0x36 and another
// with 0x5c.
fn create_keys<D: Digest>(digest: &mut D, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut i_key = expand_key(digest, key);
    let mut o_key = i_key.clone();
    derive_key(&mut i_key, 0x36);
    derive_key(&mut o_key, 0x5c);
    (i_key, o_key)
}

impl <D: Digest> Hmac<D> {
    /**
     * Create a new Hmac instance.
     *
     * # Arguments
     * * digest - The Digest to use.
     * * key - The key to use.
     *
     */
    pub fn new(mut digest: D, key: &[u8]) -> Hmac<D> {
        let (i_key, o_key) = create_keys(&mut digest, key);
        digest.input(&i_key[..]);
        Hmac {
            digest: digest,
            i_key: i_key,
            o_key: o_key,
            finished: false
        }
    }
}

impl <D: Digest> Mac for Hmac<D> {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        self.digest.input(data);
    }

    fn reset(&mut self) {
        self.digest.reset();
        self.digest.input(&self.i_key[..]);
        self.finished = false;
    }

    fn result(&mut self) -> MacResult {
        let output_size = self.digest.output_bytes();
        let mut code: Vec<u8> = repeat(0).take(output_size).collect();

        self.raw_result(&mut code);

        MacResult::new_from_owned(code)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        if !self.finished {
            self.digest.result(output);

            self.digest.reset();
            self.digest.input(&self.o_key[..]);
            self.digest.input(output);

            self.finished = true;
        }

        self.digest.result(output);
    }

    fn output_bytes(&self) -> usize { self.digest.output_bytes() }
}

#[cfg(test)]
mod test {
    use std::iter::repeat;

    use mac::Mac;
    use hmac::Hmac;
    use sha2::Sha256;

    struct Test {
        key: Vec<u8>,
        data: Vec<u8>,
        expected: Vec<u8>
    }

    // Test vectors from: http://tools.ietf.org/html/rfc2104

    fn tests() -> Vec<Test> {
        vec![
            Test {
                key: repeat(0x0bu8).take(20).collect(),
                data: b"Hi There".to_vec(),
                expected: vec![0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,],
            },
            Test {
                key: b"Jefe".to_vec(),
                data: b"what do ya want for nothing?".to_vec(),
                expected: vec![0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43],
            },
            Test {
                key: repeat(0xaau8).take(20).collect(),
                data: repeat(0xddu8).take(50).collect(),
                expected: vec![0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe, ],
            }
        ]
    }

    #[test]
    fn hmac_sha256() {
        for t in tests().iter() {
            let mut h = Hmac::new(Sha256::new(), &t.key[..]);
            let mut output = [0u8;32];
            h.input(&t.data[..]);
            h.raw_result(&mut output);
            assert_eq!(&output[..], &t.expected[..]);
        }
    }
}
