/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.channel;

import com.vanillasource.noise.Channel;
import com.vanillasource.noise.crypto.SharedKey;
import com.vanillasource.noise.crypto.CryptoSuite;
import com.vanillasource.serdes.Serdes;
import static com.vanillasource.serdes.tuple.Tuples.*;
import static com.vanillasource.serdes.seq.Sequences.*;
import static com.vanillasource.serdes.seq.SerdesFactory.*;

public final class SharedKeyChannel implements Channel {
   private final CryptoSuite cryptoSuite;
   private final SharedKey sendKey;
   private final SharedKey receiveKey;

   public SharedKeyChannel(CryptoSuite cryptoSuite, SharedKey sendKey, SharedKey receiveKey) {
      this.cryptoSuite = cryptoSuite;
      this.sendKey = sendKey;
      this.receiveKey = receiveKey;
   }

   @Override
   public void rekeySender() {
      sendKey.rekey();
   }

   @Override
   public void rekeyReceiver() {
      receiveKey.rekey();
   }

   @Override
   public byte[] sendAuthenticated(long nonce, byte[] message, int padTo) {
      return sendKey.encryptAuthenticated(nonce, cryptoSuite.emptyHash(), cryptoSuite.plaintext(message).padTo(padTo)).toBytes();
   }

   @Override
   public byte[] sendAuthenticated(long nonce, byte[] message) {
      return sendKey.encryptAuthenticated(nonce, cryptoSuite.emptyHash(), cryptoSuite.plaintext(message)).toBytes();
   }

   @Override
   public byte[] sendUnauthenticated(long nonce, byte[] message) {
      return sendKey.encryptUnauthenticated(nonce, cryptoSuite.plaintext(message)).toBytes();
   }

   @Override
   public byte[] receiveAuthenticated(long nonce, byte[] message) {
      return receiveKey.decryptAuthenticated(nonce, cryptoSuite.emptyHash(), cryptoSuite.ciphertext(message)).toBytes();
   }

   @Override
   public byte[] receiveUnauthenticated(long nonce, byte[] message) {
      return receiveKey.decryptUnauthenticated(nonce, cryptoSuite.ciphertext(message)).toBytes();
   }

   public static Serdes<Channel> serdes(CryptoSuite crypto) {
      return seq(
         crypto.sharedKeySerdes(),
         independent(crypto.sharedKeySerdes()))
         .map((o) -> tuple(((SharedKeyChannel)o).sendKey, ((SharedKeyChannel)o).receiveKey),
              tuple -> new SharedKeyChannel(crypto, tuple.a, tuple.b));
   }
}
