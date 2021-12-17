/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.protocol;

import com.vanillasource.noise.pattern.PatternMachine;
import com.vanillasource.noise.crypto.CryptoSuite;
import com.vanillasource.noise.crypto.Hash;
import com.vanillasource.noise.crypto.SharedKey;
import com.vanillasource.noise.crypto.Ciphertext;
import com.vanillasource.noise.crypto.Plaintext;
import com.vanillasource.noise.crypto.PrivateKey;
import com.vanillasource.noise.crypto.PublicKey;
import com.vanillasource.noise.crypto.SharedSecret;
import com.vanillasource.noise.Channel;
import static com.vanillasource.serdes.basic.Serdeses.*;
import static com.vanillasource.serdes.tuple.Tuples.*;
import static com.vanillasource.serdes.seq.Sequences.*;
import static com.vanillasource.serdes.seq.SerdesFactory.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.vanillasource.noise.Handshake;
import java.util.Optional;
import java.io.ByteArrayOutputStream;
import com.vanillasource.noise.pattern.Pattern;
import java.io.ByteArrayInputStream;
import java.io.UncheckedIOException;
import java.io.IOException;
import com.vanillasource.serdes.Serializer;
import com.vanillasource.serdes.Serdes;

public final class HandshakeState implements PatternMachine {
   private static final Logger LOGGER = LoggerFactory.getLogger(HandshakeState.class);
   private final CryptoSuite cryptoSuite;
   private final Pattern.Execution execution;
   private PrivateKey localStaticKey, localEphemeralKey;
   private PublicKey remoteStaticKey, remoteEphemeralKey;
   private SymmetricState symmetricState;
   private transient ByteArrayOutputStream byteOutput;
   private transient DataOutputStream dataOutput;
   private transient ByteArrayInputStream byteInput;
   private transient DataInputStream dataInput;
   private transient List<SharedKey> transportKeys;

   public HandshakeState(CryptoSuite cryptoSuite, Pattern pattern, boolean initiator,
         PrivateKey localStaticKey, PublicKey remoteStaticKey) {
      this(cryptoSuite, SymmetricState.initialize(cryptoSuite, pattern), pattern,
            pattern.execute(initiator), localStaticKey, remoteStaticKey, null, null);
      this.symmetricState.mixHash(cryptoSuite.plaintext(new byte[] {})); // Prologue
   }

   public HandshakeState(CryptoSuite cryptoSuite, SymmetricState symmetricState, Pattern pattern, Pattern.Execution execution,
         PrivateKey localStaticKey, PublicKey remoteStaticKey, PrivateKey localEphemeralKey, PublicKey remoteEphemeralKey) {
      this.cryptoSuite = cryptoSuite;
      this.symmetricState = symmetricState;
      this.localStaticKey = localStaticKey;
      this.remoteStaticKey = remoteStaticKey;
      this.localEphemeralKey = localEphemeralKey;
      this.remoteEphemeralKey = remoteEphemeralKey;
      this.execution = execution;
   }

   public byte[] send(byte[] message) {
      byteOutput = new ByteArrayOutputStream();
      dataOutput = new DataOutputStream(byteOutput);
      execution.nextLineForLocal(this);
      symmetricState
         .encryptAndHash(cryptoSuite.plaintext(message))
         .writeInto(dataOutput);
      return byteOutput.toByteArray();
   }

   public byte[] receive(byte[] message) {
      byteInput = new ByteArrayInputStream(message);
      dataInput = new DataInputStream(byteInput);
      execution.nextLineForRemote(this);
      byte[] remainingBytes = new byte[byteInput.available()];
      try {
         dataInput.readFully(remainingBytes);
      } catch (IOException e) {
         throw new UncheckedIOException(e);
      }
      return symmetricState.decryptAndHash(cryptoSuite.ciphertext(remainingBytes)).toBytes();
   }

   public Optional<List<SharedKey>> tryEstablish() {
      return Optional.ofNullable(transportKeys);
   }

   @Override
   public void establish() {
      transportKeys = symmetricState.split();
   }

   @Override
   public void localSendsEphemeralKey(){
      if (localEphemeralKey != null) {
         throw new IllegalStateException("local ephemeral key was already present");
      }
      localEphemeralKey = cryptoSuite.generatePrivateKey();
      symmetricState.mixHash(localEphemeralKey.getPublicKey());
      localEphemeralKey.getPublicKey().writeInto(dataOutput);
   }

   @Override
   public void remoteSendsEphemeralKey(){
      if (remoteEphemeralKey != null) {
         throw new IllegalStateException("remote ephemeral key was already present");
      }
      remoteEphemeralKey = cryptoSuite.readPublicKey(dataInput);
      symmetricState.mixHash(remoteEphemeralKey);
   }

   @Override
   public void localSendsStaticKey(){
      symmetricState
         .encryptAndHash(localStaticKey.getPublicKey().toPlaintext())
         .writeInto(dataOutput);
   }

   @Override
   public void remoteSendsStaticKey(){
      if (remoteStaticKey != null) {
         throw new IllegalStateException("remote static key was already present");
      }
      if (symmetricState.hasKey()) {
         Ciphertext encryptedPublicKey = cryptoSuite.readEncryptedPublicKey(dataInput);
         remoteStaticKey = symmetricState.decryptAndHash(encryptedPublicKey).toPublicKey();
      } else {
         remoteStaticKey = cryptoSuite.readPublicKey(dataInput);
         symmetricState.mixHash(remoteStaticKey);
      }
   }

   @Override
   public void negotiateEphemeralKeys(){
      symmetricState.mixKey(localEphemeralKey, remoteEphemeralKey);
   }

   @Override
   public void negotiateStaticKeys() {
      symmetricState.mixKey(localStaticKey, remoteStaticKey);
   }

   @Override
   public void negotiateLocalEphemeralWithRemoteStaticKey() {
      symmetricState.mixKey(localEphemeralKey, remoteStaticKey);
   }

   @Override
   public void negotiateLocalStaticWithRemoteEphemeralKey() {
      symmetricState.mixKey(localStaticKey, remoteEphemeralKey);
   }

   @Override
   public void localStaticKeyPreMessage() {
      if (localStaticKey == null) {
         throw new IllegalStateException("pre-shared local static key not present");
      }
      symmetricState.mixHash(localStaticKey.getPublicKey());
   }

   @Override
   public void remoteStaticKeyPreMessage() {
      if (remoteStaticKey == null) {
         throw new IllegalStateException("pre-shared remote static key not present");
      }
      symmetricState.mixHash(remoteStaticKey);
   }

   public static Serdes<HandshakeState> serdes(CryptoSuite crypto, Pattern pattern, 
         PrivateKey localStaticKey, PublicKey remoteStaticKey) {
      return seq(
         Pattern.Execution.serdes(pattern),
         independent(nullable(crypto.privateKeySerdes())),
         independent(nullable(crypto.publicKeySerdes())),
         independent(SymmetricState.serdes(crypto)))
         .map(o -> tuple(o.execution, o.localEphemeralKey, o.remoteEphemeralKey, o.symmetricState),
              t -> new HandshakeState(crypto, t.d, pattern, t.a, localStaticKey, remoteStaticKey,
                 t.b, t.c));
   }
}
