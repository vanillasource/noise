/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto;

import java.io.DataOutput;

public interface Plaintext {
   Plaintext padTo(int length);

   PublicKey toPublicKey();

   Ciphertext toCiphertext();

   Hash mixInto(Hash hash);

   void writeInto(DataOutput output);

   byte[] toBytes();

   boolean isEmpty();
}

