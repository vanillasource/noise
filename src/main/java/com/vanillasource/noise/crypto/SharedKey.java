/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto;

import java.util.List;
import static java.util.Collections.nCopies;

public interface SharedKey {
   Ciphertext encryptAuthenticated(long counter, Hash ad, Plaintext plaintext);

   Ciphertext encryptUnauthenticated(long counter, Plaintext plaintext);

   Plaintext decryptAuthenticated(long counter, Hash ad, Ciphertext ciphertext);

   Plaintext decryptUnauthenticated(long counter, Ciphertext ciphertext);

   SharedKey rekey();
}
