/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise;

/**
 * Represents an established full-duplex channel of communication
 * between two parties.
 */
public interface Channel {
   /**
    * Encrypt an arbitrary (but maximum 65535-overhead) bytes
    * of message with the given nonce. Note: caller is responsible
    * for padding.
    * @param message The plaintext message bytes.
    * @param padTo Pad the message to be exactly this many bytes with authentication code.
    * @return The transport message with authentication code.
    */
   byte[] sendAuthenticated(long nonce, byte[] message, int padTo);

   byte[] sendAuthenticated(long nonce, byte[] message);

   /**
    * Encrypt a non-authenticated message. This will result in the same amount
    * of bytes. Note: Message may be arbitrarily modified by attackers. Only
    * use if that is not a problem for use-case.
    * @param message The plaintext message bytes. At most one block length.
    * @return The transport message without authentication.
    */
   byte[] sendUnauthenticated(long nonce, byte[] message);

   /**
    * Decrypt a received message with authentication code.
    * @param message The encrypted and authenticated message.
    * @return The plaintext message. Note, message may have extra padding
    * after the payload. It is the callers responsibility to know the
    * exact payload length, if it is needed.
    */
   byte[] receiveAuthenticated(long nonce, byte[] message);

   /**
    * Decrypt a received non-authenticated message. Note: Message
    * may have been tampered with. Decryption will always work, even
    * if the data is garbage!
    * @param message The encrypted and authenticated message. At most one block length.
    * @return The plaintext message, which may have been tampered.
    */
   byte[] receiveUnauthenticated(long nonce, byte[] message);

   void rekeySender();

   void rekeyReceiver();
}

