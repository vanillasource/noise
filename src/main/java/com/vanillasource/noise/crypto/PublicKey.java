/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto;

import java.io.DataOutput;

public interface PublicKey {
   Hash mixInto(Hash hash);

   Plaintext toPlaintext();

   void writeInto(DataOutput output);

   byte[] serialize();

   boolean sameAs(PublicKey otherPublicKey);
}
