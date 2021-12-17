/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.channel;

import com.vanillasource.noise.crypto.CryptoSuite;
import com.vanillasource.noise.crypto.PrivateKey;
import com.vanillasource.noise.crypto.PublicKey;
import com.vanillasource.noise.pattern.Pattern;
import com.vanillasource.noise.pattern.Pattern.Execution;
import com.vanillasource.noise.Handshake;
import com.vanillasource.noise.Channel;
import java.util.concurrent.CompletableFuture;
import com.vanillasource.noise.crypto.Hash;
import com.vanillasource.noise.protocol.HandshakeState;
import java.util.Optional;
import com.vanillasource.serdes.Serdes;

public final class Noise {
   private final boolean initiator;
   private final CryptoSuite cryptoSuite;
   private final Pattern pattern;
   private PrivateKey localStaticKey;
   private PublicKey remoteStaticKey;

   private Noise(boolean initiator, CryptoSuite cryptoSuite, Pattern pattern) {
      this.initiator = initiator;
      this.cryptoSuite = cryptoSuite;
      this.pattern = pattern;
   }

   public static Noise newNoise(boolean initiator, CryptoSuite cryptoSuite, Pattern pattern) {
      return new Noise(initiator, cryptoSuite, pattern);
   }

   public static Noise newInitiator(CryptoSuite cryptoSuite, Pattern pattern) {
      return new Noise(true, cryptoSuite, pattern);
   }

   public static Noise newResponder(CryptoSuite cryptoSuite, Pattern pattern) {
      return new Noise(false, cryptoSuite, pattern);
   }

   public Noise withLocalStaticKey(PrivateKey localStaticKey) {
      this.localStaticKey = localStaticKey;
      return this;
   }

   public Noise withRemoteStaticKey(PublicKey remoteStaticKey) {
      this.remoteStaticKey = remoteStaticKey;
      return this;
   }

   public Handshake initialize() {
      return new HandshakeStateHandshake(new HandshakeState(cryptoSuite, pattern, initiator,
            localStaticKey, remoteStaticKey));
   }

   public Serdes<Handshake> handshakeSerdes() {
      return HandshakeState.serdes(cryptoSuite, pattern, localStaticKey, remoteStaticKey)
         .map(h -> ((HandshakeStateHandshake)h).handshakeState, HandshakeStateHandshake::new);
   }

   public static Serdes<Channel> channelSerdes(CryptoSuite cryptoSuite) {
      return SharedKeyChannel.serdes(cryptoSuite);
   }

   private final class HandshakeStateHandshake implements Handshake {
      private final HandshakeState handshakeState;

      private HandshakeStateHandshake(HandshakeState handshakeState) {
         this.handshakeState = handshakeState;
      }

      @Override
      public byte[] send(byte[] message) {
         return handshakeState.send(message);
      }

      @Override
      public byte[] receive(byte[] message) {
         return handshakeState.receive(message);
      }

      @Override
      public Optional<Channel> tryEstablish() {
         return handshakeState.tryEstablish()
            .map(transportKeys -> {
               return new SharedKeyChannel(cryptoSuite,
                     transportKeys.get(initiator?0:1),
                     transportKeys.get(initiator?1:0));
            });
      }
   }
}

