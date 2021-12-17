/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto.Curve25519_AESGCM_SHA256;

import org.testng.annotations.Test;
import static org.testng.Assert.*;
import com.vanillasource.noise.channel.Noise;
import com.vanillasource.noise.pattern.Fundamentals;
import java.util.concurrent.CompletableFuture;
import com.southernstorm.noise.protocol.HandshakeState;
import com.vanillasource.noise.Handshake;
import java.util.Arrays;
import java.math.BigInteger;
import com.vanillasource.noise.Channel;
import java.util.Optional;
import com.southernstorm.noise.protocol.CipherStatePair;

@Test
public final class CompatibilityITTests {

   public void testInitiateExchangeMessages() throws Exception {
      HandshakeState remoteHandshake = createRemoteHandshake(false);
      Handshake localHandshake = createLocalHandshake(true);

      // Play handshake
      byte[] sentMessage1 = sendLocal(localHandshake, new byte[] {});
      byte[] receivedPayload1 = receiveRemote(remoteHandshake, sentMessage1);
      byte[] sentMessage2 = sendRemote(remoteHandshake, new byte[] {});
      byte[] receivedPayload2 = receiveLocal(localHandshake, sentMessage2);

      // Channel can be established
      CipherStatePair remoteChannel = remoteHandshake.split();
      Channel localChannel = localHandshake.tryEstablish().get();

      // Send message
      byte[] sentTransportMessage1 = localChannel.sendAuthenticated(0L, new byte[] { 1, 2, 3 });
      byte[] receivedPlaintext1 = receiveRemote(remoteChannel, sentTransportMessage1);
      assertEquals(receivedPlaintext1, new byte[] { 1, 2, 3 });

      // Receive message
      byte[] sentTransportMessage2 = sendRemote(remoteChannel, new byte[] { 1, 2, 3 });
      byte[] receivedPlaintext2 = localChannel.receiveAuthenticated(0L, sentTransportMessage2);
      assertEquals(receivedPlaintext2, new byte[] { 1, 2, 3 });

      // Send message 2
      byte[] sentTransportMessage3 = localChannel.sendAuthenticated(1L, new byte[] { 1, 2, 3 });
      byte[] receivedPlaintext3 = receiveRemote(remoteChannel, sentTransportMessage3);
      assertEquals(receivedPlaintext3, new byte[] { 1, 2, 3 });

      // Receive message 2
      byte[] sentTransportMessage4 = sendRemote(remoteChannel, new byte[] { 1, 2, 3 });
      byte[] receivedPlaintext4 = localChannel.receiveAuthenticated(1L, sentTransportMessage4);
      assertEquals(receivedPlaintext4, new byte[] { 1, 2, 3 });
   }

   public void testRespondExchangeMessages() throws Exception {
      HandshakeState remoteHandshake = createRemoteHandshake(true);
      Handshake localHandshake = createLocalHandshake(false);

      // Play handshake
      byte[] sentMessage1 = sendRemote(remoteHandshake, new byte[] {});
      byte[] receivedPayload1 = receiveLocal(localHandshake, sentMessage1);
      byte[] sentMessage2 = sendLocal(localHandshake, new byte[] {});
      byte[] receivedPayload2 = receiveRemote(remoteHandshake, sentMessage2);

      // Channel can be established
      CipherStatePair remoteChannel = remoteHandshake.split();
      Channel localChannel = localHandshake.tryEstablish().get();

      // Send message
      byte[] sentTransportMessage1 = localChannel.sendAuthenticated(0L, new byte[] { 1, 2, 3 });
      byte[] receivedPlaintext1 = receiveRemote(remoteChannel, sentTransportMessage1);
      assertEquals(receivedPlaintext1, new byte[] { 1, 2, 3 });

      // Receive message
      byte[] sentTransportMessage2 = sendRemote(remoteChannel, new byte[] { 1, 2, 3 });
      byte[] receivedPlaintext2 = localChannel.receiveAuthenticated(0L, sentTransportMessage2);
      assertEquals(receivedPlaintext2, new byte[] { 1, 2, 3 });
   }

   private Handshake createLocalHandshake(boolean initiator) {
      if (initiator) {
         return Noise.newInitiator(new Curve25519AESGCMSHA256CryptoSuite(), Fundamentals.NN)
            .initialize();
      } else {
         return Noise.newResponder(new Curve25519AESGCMSHA256CryptoSuite(), Fundamentals.NN)
            .initialize();
      }
   }

   private HandshakeState createRemoteHandshake(boolean initiator) throws Exception {
      HandshakeState state = new HandshakeState("Noise_NN_25519_AESGCM_SHA256", initiator?HandshakeState.INITIATOR:HandshakeState.RESPONDER);
      state.start();
      return state;
   }

   private byte[] sendLocal(Handshake localHandshake, byte[] message) {
      byte[] localOutgoingMessage = localHandshake.send(new byte[] {});
      System.out.println(" -> "+new BigInteger(localOutgoingMessage).toString(16)+" ("+localOutgoingMessage.length+")");
      return localOutgoingMessage;
   }

   private byte[] receiveRemote(HandshakeState remoteHandshake, byte[] message) throws Exception {
      byte[] payload = new byte[1024];
      int payloadLength = remoteHandshake.readMessage(message, 0, message.length, payload, 0);
      return Arrays.copyOfRange(payload, 0, payloadLength);
   }

   private byte[] sendRemote(HandshakeState remoteHandshake, byte[] message) throws Exception {
      byte[] remoteOutgoingMessage = new byte[1024];
      int remoteOutgoingMessageLength = remoteHandshake.writeMessage(remoteOutgoingMessage, 0, message, 0, message.length);
      if (remoteOutgoingMessageLength == 0) {
         System.out.println(" <- (nothing)"); 
      } else {
         System.out.println(" <- "+new BigInteger(Arrays.copyOfRange(remoteOutgoingMessage, 0, remoteOutgoingMessageLength)).toString(16)+" ("+remoteOutgoingMessageLength+")");
      }
      return Arrays.copyOfRange(remoteOutgoingMessage, 0, remoteOutgoingMessageLength);
   }

   private byte[] receiveLocal(Handshake localHandshake, byte[] message) {
      return localHandshake.receive(message);
   }

   private byte[] receiveRemote(CipherStatePair remoteChannel, byte[] message) throws Exception {
      byte[] receivedPlaintext = new byte[message.length];
      int receivedPlaintextLength = remoteChannel.getReceiver().decryptWithAd(null, message, 0, receivedPlaintext, 0, receivedPlaintext.length);
      return Arrays.copyOfRange(receivedPlaintext, 0, receivedPlaintextLength);
   }

   private byte[] sendRemote(CipherStatePair remoteChannel, byte[] message) throws Exception {
      byte[] sendCiphertext = new byte[1024];
      int sendCiphertextLength = remoteChannel.getSender().encryptWithAd(null, message, 0, sendCiphertext, 0, message.length);
      return Arrays.copyOfRange(sendCiphertext, 0, sendCiphertextLength);
   }
}


