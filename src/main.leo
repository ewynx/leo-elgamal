// The 'el_gamal' program.
program el_gamal.aleo {
  struct Ciphertext {
    c1: field,
    c2: field
  }

    // Step 1: encrypt
    // m message
    // pub_key to encrypt msg under
    // k random value - there's a function ChaCha::rand_field(), but it can only be used in a `finalize` block
    // gen generator of field
    // GENERATOR = 22 source https://github.com/AleoHQ/snarkVM/blob/testnet3/curves/src/bls12_377/fr.rs#L124
    transition encrypt(m: field, pub_key: field, k: field) -> Ciphertext {
        let c1: field = 22field.pow(k);
        let c2: field = m * pub_key.pow(k);
        return Ciphertext {
          c1: c1,
          c2: c2
        };
    }

    transition get_pub_key(s: field) -> field {
      return 22field.pow(s);
    }

  // Step 2: perform homomorphic addition. The multiplication of ciphertexts corresponds to addition of the plaintexts, encrypted
  // Note: ciphertexts must be encrypted under same key
    transition mult_ciphertexts(inp1: Ciphertext, inp2: Ciphertext) -> Ciphertext {
      return Ciphertext {
          c1: inp1.c1 * inp2.c1,
          c2: inp1.c2 * inp2.c2
        };
    }

  // Step 3: Decrypt
    transition decrypt(final_ciph: Ciphertext, priv_key: field) -> field {
      let s_a: field = (final_ciph.c1.pow(priv_key)).inv();
      return final_ciph.c2 * s_a;
    }
}
