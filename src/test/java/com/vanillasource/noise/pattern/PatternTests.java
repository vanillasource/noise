/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.pattern;

import com.vanillasource.noise.pattern.Pattern.Execution;
import org.testng.annotations.Test;
import static org.testng.Assert.*;
import org.testng.annotations.BeforeMethod;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.*;
import static com.vanillasource.noise.pattern.Fundamentals.*;
import org.mockito.InOrder;
import java.util.concurrent.CompletableFuture;

@Test
public final class PatternTests {
   private PatternMachine machine;

   @Test(expectedExceptions = IllegalArgumentException.class)
   public void testEmptyPatternIsInvalid() {
      Pattern pattern = Pattern.of("TEST", asList(""));
   }

   @Test(expectedExceptions = IllegalArgumentException.class)
   public void testArrowOnlyIsInvalid() {
      Pattern pattern = Pattern.of("TEST", asList("-> "));
   }

   public void testLocalECallsLocalSendEphemeral() {
      Pattern pattern = Pattern.of("TEST", asList("-> e"));

      pattern.execute(true).nextLineForLocal(machine);

      verify(machine).localSendsEphemeralKey();
   }

   public void testPreMessageCanBeReceiveFirstAndStillBeCanonical() {
      Pattern.of("TEST", asList("<- s", "...", "-> e"));
   }

   public void testLocalECallsPreMessageIfBeforePoints() {
      Pattern pattern = Pattern.of("TEST", asList("-> s", "...", "-> e"));

      pattern.execute(true).nextLineForLocal(machine);

      verify(machine).localStaticKeyPreMessage();
   }

   public void testPreMessagesAreSkipped() {
      Pattern pattern = Pattern.of("TEST", asList("-> s", "...", "-> e"));

      pattern.execute(true).nextLineForLocal(machine);

      verify(machine).localStaticKeyPreMessage();
      verify(machine).localSendsEphemeralKey();
   }

   public void testRemoteECallsRemoteSendEphemeral() {
      Pattern pattern = Pattern.of("TEST", asList("-> e", "<- e"));

      pattern.execute(true)
         .nextLineForLocal(machine)
         .nextLineForRemote(machine);

      verify(machine).remoteSendsEphemeralKey();
   }

   public void testExecutionCompletesIfSendWorks() {
      Pattern pattern = Pattern.of("TEST", asList("-> e"));

      pattern.execute(true).nextLineForLocal(machine);

      verify(machine).localSendsEphemeralKey();
      verify(machine).establish();
   }

   public void testNNStepsAccordingToPlan() {
      NN.execute(true)
         .nextLineForLocal(machine)
         .nextLineForRemote(machine);

      InOrder order = inOrder(machine);
      order.verify(machine).localSendsEphemeralKey();
      order.verify(machine).remoteSendsEphemeralKey();
      order.verify(machine).negotiateEphemeralKeys();
      order.verify(machine).establish();
      order.verifyNoMoreInteractions();
   }

   public void testPatternNameIsTheName() {
      assertEquals(NN.getName(), "NN");
   }

   public void testPatternModifierIsAppendedToName() {
      Pattern pattern = Pattern.of("TEST", asList("e"), asList("-> e"));

      assertEquals(pattern.getName(), "TESTe");
   }

   public void testPatternModifiersAreConcatenatedWithPlus() {
      Pattern pattern = Pattern.of("TEST", asList("e", "psk0"), asList("-> e"));

      assertEquals(pattern.getName(), "TESTe+psk0");
   }

   @BeforeMethod
   protected void setUp() {
      machine = mock(PatternMachine.class);
   }
}
