/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto;

import java.util.List;

public interface Hash {
   List<Hash> derive(SharedSecret sharedSecret, int parts);

   List<Hash> derive(int parts);

   SharedKey toKey();
}

