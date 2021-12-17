/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.crypto.Curve25519_AESGCM_SHA256;

import com.vanillasource.noise.crypto.*;
import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.DataInput;
import java.io.IOException;
import java.security.SecureRandom;
import java.io.DataOutput;
import java.util.List;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.math.BigInteger;
import java.io.UncheckedIOException;
import com.vanillasource.serdes.Serdes;
import static com.vanillasource.serdes.basic.Serdeses.*;

public final class Curve25519AESGCMSHA256CryptoSuite implements CryptoSuite {
   private static final Logger LOGGER = LoggerFactory.getLogger(Curve25519AESGCMSHA256CryptoSuite.class);
   private final SecureRandom rnd = new SecureRandom();

   @Override
   public String getName() {
      return "25519_AESGCM_SHA256";
   }

   @Override
   public PrivateKey generatePrivateKey() {
      byte[] publicKey = new byte[Curve25519.KEY_SIZE];
      byte[] privateSigningKey = new byte[Curve25519.KEY_SIZE];
      byte[] privateAgreementKey = new byte[Curve25519.KEY_SIZE];
      rnd.nextBytes(privateAgreementKey);
      Curve25519.keygen(publicKey, privateSigningKey, privateAgreementKey);
      return new BytePrivateKey(publicKey, privateAgreementKey);
   }

   @Override
   public PublicKey readPublicKey(DataInput input) {
      try {
         byte[] publicKey = new byte[Curve25519.KEY_SIZE];
         input.readFully(publicKey);
         return new BytePublicKey(publicKey);
      } catch (IOException e) {
         throw new UncheckedIOException(e);
      }
   }

   @Override
   public PublicKey deserializePublicKey(byte[] bytes) {
      if (bytes.length != Curve25519.KEY_SIZE) {
         throw new IllegalArgumentException("bytes to deserialize were not "+Curve25519.KEY_SIZE+" bytes as the Curve requires");
      }
      return new BytePublicKey(bytes);
   }

   @Override
   public PrivateKey deserializePrivateKey(byte[] bytes) {
      if (bytes.length != 2*Curve25519.KEY_SIZE) {
         throw new IllegalArgumentException("bytes to deserialize were not "+Curve25519.KEY_SIZE+" bytes as the Curve requires");
      }
      return new BytePrivateKey(Arrays.copyOfRange(bytes, 0, Curve25519.KEY_SIZE),
              Arrays.copyOfRange(bytes, Curve25519.KEY_SIZE, 2*Curve25519.KEY_SIZE));
   }

   @Override
   public Ciphertext readEncryptedPublicKey(DataInput input) {
      try {
         byte[] ciphertext = new byte[32 + 16];
         input.readFully(ciphertext);
         return new ByteCiphertext(ciphertext);
      } catch (IOException e) {
         throw new UncheckedIOException(e);
      }
   }

   @Override
   public Plaintext plaintext(byte[] bytes) {
      return new BytePlaintext(bytes);
   }

   @Override
   public Ciphertext ciphertext(byte[] bytes) {
      return new ByteCiphertext(bytes);
   }

   @Override
   public Hash hashProtocolName(String protocolName) {
      try {
         byte[] protocolNameBytes = protocolName.getBytes("UTF-8");
         Hash hash;
         if (protocolNameBytes.length < 32) {
            byte[] data = new byte[32];
            System.arraycopy(protocolNameBytes, 0, data, 0, protocolNameBytes.length);
            hash = new ByteHash(data);
         } else {
            hash = ByteHash.of(protocolNameBytes);
         }
         if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("protocol name hash={}", hash);
         }
         return hash;
      } catch (Exception e) {
         throw new IllegalStateException("can not hash protocol name", e);
      }
   }

   @Override
   public Hash emptyHash() {
      return new ByteHash(new byte[] {});
   }

   public static final class BytePrivateKey implements PrivateKey {
      private final byte[] publicKey;
      private final byte[] privateKey;

      public BytePrivateKey(byte[] publicKey, byte[] privateKey) {
         this.publicKey = publicKey;
         this.privateKey = privateKey;
      }

      @Override
      public SharedSecret dh(PublicKey remoteKey) {
         byte[] sharedSecret = new byte[Curve25519.KEY_SIZE];
         Curve25519.curve(sharedSecret, privateKey, ((BytePublicKey)remoteKey).publicKey);
         if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("dh="+new BigInteger(sharedSecret).toString(16));
         }
         return new ByteSharedSecret(sharedSecret);
      }

      @Override
      public PublicKey getPublicKey() {
         return new BytePublicKey(publicKey);
      }

      @Override
      public byte[] serialize() {
          byte[] bytes = new byte[publicKey.length + privateKey.length];
          System.arraycopy(publicKey, 0, bytes, 0, publicKey.length);
          System.arraycopy(privateKey, 0, bytes, publicKey.length, privateKey.length);
          return bytes;
      }
   }

   public static final class ByteSharedSecret implements SharedSecret {
      private final byte[] sharedSecret;

      public ByteSharedSecret(byte[] sharedSecret) {
         this.sharedSecret = sharedSecret;
      }

      @Override
      public String toString() {
         return new java.math.BigInteger(sharedSecret).toString(16);
      }

   }

   public static final class BytePublicKey implements PublicKey {
      private final byte[] publicKey;

      public BytePublicKey(byte[] publicKey) {
         this.publicKey = publicKey;
      }

      @Override
      public Hash mixInto(Hash hash) {
         return ((ByteHash)hash).mix(publicKey);
      }

      @Override
      public Plaintext toPlaintext() {
         return new BytePlaintext(publicKey);
      }

      @Override
      public byte[] serialize() {
         return publicKey;
      }

      @Override
      public boolean sameAs(PublicKey otherPublicKey) {
         return Arrays.equals(publicKey, ((BytePublicKey)otherPublicKey).publicKey);
      }

      @Override
      public void writeInto(DataOutput output) {
         try {
            output.write(publicKey);
         } catch (IOException e) {
            throw new UncheckedIOException(e);
         }
      }
   }

   public static final class ByteHash implements Hash {
      private byte[] hash;

      public ByteHash(byte[] hash) {
         this.hash = hash;
      }

      @Override
      public String toString() {
         if (hash.length == 0) {
            return "(empty)";
         }
         return new java.math.BigInteger(hash).toString(16);
      }

      public static Hash of(byte[] data1, byte[] data2) {
         try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data1);
            byte[] hash = digest.digest(data2);
            return new ByteHash(hash);
         } catch (Exception e) {
            throw new IllegalStateException("Can not use SHA-256", e);
         }
      }

      public static Hash of(byte[] data) {
         return of(data, new byte[] {});
      }

      public Hash mix(byte[] bytes) {
         return of(hash, bytes);
      }

      @Override
      public List<Hash> derive(SharedSecret sharedSecret, int parts) {
         byte[] tempKey = hmac(hash, ((ByteSharedSecret)sharedSecret).sharedSecret, new byte[] {});
         List<Hash> hashes = new ArrayList<>(parts);
         byte[] previousBytes = new byte[] {};
         for (int i=1; i<=parts; i++) {
            previousBytes = hmac(tempKey, previousBytes, new byte[] { (byte)(i&0xFF) });
            hashes.add(new ByteHash(previousBytes));
         }
         return hashes;
      }

      private byte[] hmac(byte[] key, byte[] data1, byte[] data2) {
         try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key, "HmacSHA256"));
            hmac.update(data1);
            byte[] result = hmac.doFinal(data2);
            return result;
         } catch (Exception e) {
            throw new IllegalStateException("Can not use HMAC-SHA-256", e);
         }
      }

      @Override
      public List<Hash> derive(int parts) {
         return derive(new ByteSharedSecret(new byte[] {}), parts);
      }

      @Override
      public SharedKey toKey() {
         return new ByteSharedKey(hash);
      }
   }

   public static final class BytePlaintext implements Plaintext {
      private byte[] plaintext;

      public BytePlaintext(byte[] plaintext) {
         this.plaintext = plaintext;
      }

      @Override
      public Plaintext padTo(int length) {
         if (plaintext.length > length-16) {
            throw new IllegalArgumentException("plaintext length "+plaintext.length+" is larger than pad to size "+length);
         }
         byte[] newPlaintext = new byte[length-16];
         System.arraycopy(plaintext, 0, newPlaintext, 0, plaintext.length);
         return new BytePlaintext(newPlaintext);
      }

      @Override
      public boolean isEmpty() {
         return plaintext.length == 0;
      }

      @Override
      public PublicKey toPublicKey() {
         return new BytePublicKey(plaintext);
      }

      @Override
      public Ciphertext toCiphertext() {
         return new ByteCiphertext(plaintext);
      }

      @Override
      public Hash mixInto(Hash hash) {
         return ((ByteHash)hash).mix(plaintext);
      }

      @Override
      public void writeInto(DataOutput output) {
         try {
            output.write(plaintext);
         } catch (IOException e) {
            throw new UncheckedIOException(e);
         }
      }

      @Override
      public byte[] toBytes() {
         return plaintext;
      }
   }

   public static final class ByteSharedKey implements SharedKey {
      private final byte[] key;

      public ByteSharedKey(byte[] key) {
         this.key = key;
      }

      @Override
      public Ciphertext encryptUnauthenticated(long counter, Plaintext plaintext) {
         try {
            if (LOGGER.isTraceEnabled()) {
               LOGGER.trace("encrypt un-authenticated counter={}, key={}", counter, this);
            }
            if (((BytePlaintext)plaintext).plaintext.length > 32) {
               throw new IllegalArgumentException("can not encrypt more than one block with unauthenticated encryption");
            }
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            byte[] iv = new byte[16];
            prepareIV(iv, counter);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return new ByteCiphertext(cipher.doFinal(((BytePlaintext) plaintext).plaintext));
         } catch (Exception e) {
            throw new IllegalStateException(e);
         }
      }

      @Override
      public Ciphertext encryptAuthenticated(long counter, Hash ad, Plaintext plaintext) {
         try {
            if (LOGGER.isTraceEnabled()) {
               LOGGER.trace("encrypt authenticated counter={}, key={}, ad={}", counter, this, ad);
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12];
            prepareIV(iv, counter);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(((ByteHash)ad).hash);
            return new ByteCiphertext(cipher.doFinal(((BytePlaintext) plaintext).plaintext));
         } catch (Exception e) {
            throw new IllegalStateException(e);
         }
      }

      @Override
      public Plaintext decryptAuthenticated(long counter, Hash ad, Ciphertext ciphertext) {
         try {
            if (LOGGER.isTraceEnabled()) {
               LOGGER.trace("decrypt authenticated counter={}, key={}, ad={}", counter, this, ad);
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12];
            prepareIV(iv, counter);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(((ByteHash)ad).hash);
            return new BytePlaintext(cipher.doFinal(((ByteCiphertext) ciphertext).ciphertext));
         } catch (Exception e) {
            throw new IllegalStateException(e);
         }
      }

      @Override
      public Plaintext decryptUnauthenticated(long counter, Ciphertext ciphertext) {
         try {
            if (LOGGER.isTraceEnabled()) {
               LOGGER.trace("decrypt un-authenticated counter={}, key={}", counter, this);
            }
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            byte[] iv = new byte[16];
            prepareIV(iv, counter);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return new BytePlaintext(cipher.doFinal(((ByteCiphertext) ciphertext).ciphertext));
         } catch (Exception e) {
            throw new IllegalStateException(e);
         }
      }

      private void prepareIV(byte[] iv, long counter) {
         iv[0] = 0;
         iv[1] = 0;
         iv[2] = 0;
         iv[3] = 0;
         iv[4] = (byte) ((counter>>56)&0xFF);
         iv[5] = (byte) ((counter>>48)&0xFF);
         iv[6] = (byte) ((counter>>40)&0xFF);
         iv[7] = (byte) ((counter>>32)&0xFF);
         iv[8] = (byte) ((counter>>24)&0xFF);
         iv[9] = (byte) ((counter>>16)&0xFF);
         iv[10] = (byte) ((counter>>8)&0xFF);
         iv[11] = (byte) (counter&0xFF);
      }

      @Override
      public String toString() {
         return new java.math.BigInteger(key).toString(16);
      }

      @Override
      public SharedKey rekey() {
         return ((ByteCiphertext)encryptAuthenticated(-1, new ByteHash(new byte[] {}),
               new BytePlaintext(new byte[] { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 })))
            .toSharedKey();
      }
   }

   public static final class ByteCiphertext implements Ciphertext {
      private byte[] ciphertext;

      public ByteCiphertext(byte[] ciphertext) {
         this.ciphertext = ciphertext;
      }

      @Override
      public Ciphertext padTo(int length) {
         if (ciphertext.length > length) {
            throw new IllegalArgumentException("ciphertext length "+ciphertext.length+" is larger than pad to size "+length);
         }
         byte[] newCiphertext = new byte[length];
         System.arraycopy(ciphertext, 0, newCiphertext, 0, ciphertext.length);
         byte[] randomBytes = new byte[length-ciphertext.length];
         SecureRandom rnd = new SecureRandom();
         rnd.nextBytes(randomBytes);
         System.arraycopy(randomBytes, 0, newCiphertext, ciphertext.length, randomBytes.length);
         return new ByteCiphertext(newCiphertext);
      }

      @Override
      public Plaintext toPlaintext() {
         return new BytePlaintext(ciphertext);
      }

      @Override
      public Hash mixInto(Hash hash) {
         return ((ByteHash) hash).mix(ciphertext);
      }

      @Override
      public void writeInto(DataOutput output) {
         try {
            output.write(ciphertext);
         } catch (IOException e) {
            throw new UncheckedIOException(e);
         }
      }

      @Override
      public byte[] toBytes() {
         return ciphertext;
      }

      public SharedKey toSharedKey() {
         return new ByteSharedKey(Arrays.copyOfRange(ciphertext, 0, 32));
      }
   }

   @Override
   public Serdes<Hash> hashSerdes() {
      return fixedByteArraySerdes(32)
         .map(h -> ((ByteHash)h).hash, ByteHash::new);
   }

   @Override
   public Serdes<SharedKey> sharedKeySerdes() {
      return fixedByteArraySerdes(32)
         .map(h -> ((ByteSharedKey)h).key, ByteSharedKey::new);
   }

   @Override
   public Serdes<PublicKey> publicKeySerdes() {
      return fixedByteArraySerdes(32)
         .map(h -> ((BytePublicKey)h).publicKey, BytePublicKey::new);
   }

   @Override
   public Serdes<PrivateKey> privateKeySerdes() {
      return fixedByteArraySerdes(64)
         .map(PrivateKey::serialize, this::deserializePrivateKey);
   }
}

