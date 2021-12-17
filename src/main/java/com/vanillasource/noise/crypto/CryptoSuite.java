/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto;

import java.io.DataInput;
import com.vanillasource.serdes.Serdes;

public interface CryptoSuite {
   String getName();

   PrivateKey generatePrivateKey();

   PublicKey readPublicKey(DataInput input);

   PublicKey deserializePublicKey(byte[] bytes);

   PrivateKey deserializePrivateKey(byte[] bytes);

   Ciphertext readEncryptedPublicKey(DataInput input);

   Plaintext plaintext(byte[] bytes);

   Ciphertext ciphertext(byte[] bytes);

   Hash hashProtocolName(String protocolName);

   Hash emptyHash();

   Serdes<Hash> hashSerdes();

   Serdes<SharedKey> sharedKeySerdes();

   Serdes<PublicKey> publicKeySerdes();

   Serdes<PrivateKey> privateKeySerdes();
}
