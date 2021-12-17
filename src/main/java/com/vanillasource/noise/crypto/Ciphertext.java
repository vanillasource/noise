/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto;

import java.io.DataOutput;

public interface Ciphertext {
   Ciphertext padTo(int length);

   Hash mixInto(Hash hash);

   void writeInto(DataOutput output);

   byte[] toBytes();

   Plaintext toPlaintext();
}

