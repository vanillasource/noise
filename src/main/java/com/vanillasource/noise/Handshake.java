/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise;

import java.util.Optional;

/**
 * The handshake phase of a channel establishment. The caller has
 * the responsibility to call each method in order of the pattern supplied.
 */
public interface Handshake {
   /**
    * Send the message specified with the next outgoing handshake message.
    * Note, handshake messages have varying levels of security, only send
    * if you are familiar with the pattern and the handshake.
    * @param message The message to send. May be empty.
    */
   byte[] send(byte[] message);

   /**
    * Receive a message from peer.
    * @return The message the responder sent. May be empty.
    */
   byte[] receive(byte[] message);

   /**
    * This method returns the established channel, if the handshake is over.
    * If the channel is established, there can be no other invocations.
    */
   Optional<Channel> tryEstablish();
}

