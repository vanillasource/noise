/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.pattern;

import java.util.List;

public interface PatternMachine {
   void establish();

   void localSendsEphemeralKey();

   void remoteSendsEphemeralKey();

   void localSendsStaticKey();

   void localStaticKeyPreMessage();

   void remoteSendsStaticKey();

   void remoteStaticKeyPreMessage();

   void negotiateEphemeralKeys();

   void negotiateStaticKeys();

   void negotiateLocalEphemeralWithRemoteStaticKey();

   void negotiateLocalStaticWithRemoteEphemeralKey();
}
