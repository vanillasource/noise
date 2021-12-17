/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.protocol;

import com.vanillasource.noise.crypto.Hash;
import com.vanillasource.noise.pattern.Pattern;
import com.vanillasource.noise.crypto.CryptoSuite;
import com.vanillasource.noise.crypto.Plaintext;
import com.vanillasource.noise.crypto.Ciphertext;
import com.vanillasource.noise.crypto.SharedKey;
import com.vanillasource.noise.crypto.SharedSecret;
import com.vanillasource.noise.crypto.PublicKey;
import com.vanillasource.noise.crypto.PrivateKey;
import java.util.List;
import static java.util.Arrays.asList;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import com.vanillasource.serdes.Serdes;
import static com.vanillasource.serdes.basic.Serdeses.*;
import static com.vanillasource.serdes.seq.Sequences.*;
import static com.vanillasource.serdes.tuple.Tuples.*;
import static com.vanillasource.serdes.seq.SerdesFactory.*;
import java.util.Optional;

public final class SymmetricState {
   private static final Logger LOGGER = LoggerFactory.getLogger(SymmetricState.class);
   private long nonce;
   private SharedKey key;
   private Hash hash;
   private Hash chainingKey;

   private SymmetricState(Hash hash) {
      this(0L, null, hash, hash);
   }

   private SymmetricState(long nonce, SharedKey key, Hash hash, Hash chainingKey) {
      this.nonce = nonce;
      this.key = key;
      this.hash = hash;
      this.chainingKey = chainingKey;
   }

   public boolean hasKey() {
      return key != null;
   }

   public static SymmetricState initialize(CryptoSuite cryptoSuite, Pattern pattern) {
      String protocolName = "Noise_"+pattern.getName()+"_"+cryptoSuite.getName();
      Hash initialHash = cryptoSuite.hashProtocolName(protocolName);
      return new SymmetricState(initialHash);
   }

   public void mixHash(Plaintext plaintext) {
      hash = plaintext.mixInto(hash);
   }

   public void mixHash(PublicKey publicKey) {
      hash = publicKey.mixInto(hash);
   }

   public Ciphertext encryptAndHash(Plaintext plaintext) {
      if (key != null) {
         Ciphertext ciphertext = key.encryptAuthenticated(nonce++, hash, plaintext);
         hash = ciphertext.mixInto(hash);
         return ciphertext;
      } else {
         hash = plaintext.mixInto(hash);
         return plaintext.toCiphertext();
      }
   }

   public Plaintext decryptAndHash(Ciphertext ciphertext) {
      if (key != null) {
         Plaintext plaintext = key.decryptAuthenticated(nonce++, hash, ciphertext);
         hash = ciphertext.mixInto(hash);
         return plaintext;
      } else {
         Plaintext plaintext = ciphertext.toPlaintext();
         hash = ciphertext.mixInto(hash);
         return plaintext;
      }
   }
   
   public void mixKey(PrivateKey localKey, PublicKey remoteKey) {
      SharedSecret sharedSecret = localKey.dh(remoteKey);
      if (LOGGER.isTraceEnabled()) {
         LOGGER.trace("before mixkey"
               +" input="+sharedSecret+","
               +" chainingKey="+chainingKey+","
               +" key="+key);
      }
      List<Hash> hashes = chainingKey.derive(sharedSecret, 2);
      chainingKey = hashes.get(0);
      nonce = 0L;
      key = hashes.get(1).toKey();
      if (LOGGER.isTraceEnabled()) {
         LOGGER.trace("after mixkey"
               +" chainingKey="+chainingKey+","
               +" key="+key);
      }
   }

   public List<SharedKey> split() {
      if (key == null) {
         throw new IllegalStateException("can not split, there was no key established");
      }
      List<Hash> transportKeys = chainingKey.derive(2);
      return asList(transportKeys.get(0).toKey(), transportKeys.get(1).toKey());
   }

   public static Serdes<SymmetricState> serdes(CryptoSuite crypto) {
      return seq(
         longSerdes(),
         independent(nullable(crypto.sharedKeySerdes())),
         independent(crypto.hashSerdes()),
         independent(crypto.hashSerdes()))
         .map(o -> tuple(o.nonce, o.key, o.hash, o.chainingKey),
              t -> new SymmetricState(t.a, t.b, t.c, t.d));
   }
}
