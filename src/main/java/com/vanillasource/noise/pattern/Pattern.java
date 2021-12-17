/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.pattern;

import java.util.List;
import static java.util.Arrays.asList;
import java.util.HashMap;
import java.util.Map;
import static com.vanillasource.serdes.basic.Serdeses.*;
import static com.vanillasource.serdes.tuple.Tuples.*;
import static com.vanillasource.serdes.seq.Sequences.*;
import static com.vanillasource.serdes.seq.SerdesFactory.*;
import com.vanillasource.serdes.Serdes;

/**
 * A handshake pattern, the DSL of the Noise Protocol.
 */
public final class Pattern {
   private final String name;
   private final List<String> modifiers;
   private final List<String> script;

   private Pattern(String name, List<String> modifiers, List<String> script) {
      this.name = name;
      this.modifiers = modifiers;
      this.script = script;
   }

   public String getName() {
      StringBuilder builder = new StringBuilder();
      for (String modifier: modifiers) {
         if (builder.length() > 0) {
            builder.append("+");
         }
         builder.append(modifier);
      }
      return name+builder.toString();
   }

   /**
    * Execute this pattern. If the pattern
    * finishes without exceptions, it results in an established channel.
    * @return A paused execution.
    */
   public Execution execute(boolean initiator) {
      return new Execution(script, initiator);
   }

   public static Pattern of(String name, List<String> modifiers, List<String> scriptLines) {
      Pattern candidate = new Pattern(name, modifiers, scriptLines);
      candidate.ensureNaming();
      candidate.ensureCanonical();
      candidate.ensureValidSyntax();
      candidate.ensurePublicKeysOnce();
      candidate.ensureNegotiationsOnce();
      return candidate;
   }

   public static Pattern of(String name, List<String> scriptLines) {
      return of(name, asList(), scriptLines);
   }

   private void ensureNaming() {
      if (!name.equals(name.toUpperCase())) {
         throw new IllegalArgumentException("name of pattern ("+name+") is not uppercase");
      }
      for (String modifier: modifiers) {
         if (!modifier.equals(modifier.toLowerCase())) {
            throw new IllegalArgumentException("modifier of pattern ("+modifier+") is not lowercase");
         }
      }
   }

   private void ensureValidSyntax() {
      int points = 0;
      for (String scriptLine: script) {
         if (scriptLine.equals("...")) {
            points++;
            if (points > 1) {
               throw new IllegalArgumentException("more than one '...' in script");
            }
         } else {
            if (!scriptLine.startsWith("<- ") && !scriptLine.startsWith("-> ")) {
               throw new IllegalArgumentException("script line '"+scriptLine+"' doesn't start with arrow");
            }
            if (!scriptLine.substring(3).matches("^((e|s|ee|es|se|ss), )*(e|s|ee|es|se|ss)$")) {
               throw new IllegalArgumentException("script line '"+scriptLine+"' doesn't contain valid symbols");
            }
         }
      }
   }

   private void ensureCanonical() {
      int indexOfDot = script.indexOf("...");
      int indexOfFirstPattern = 0;
      if (indexOfDot > 0) {
         indexOfFirstPattern = indexOfDot+1;
      }
      String[] symbols = script.get(indexOfFirstPattern).split(" ");
      if (!symbols[0].equals("->")) {
         throw new IllegalArgumentException("all patterns must be in Canonical (i.e. Alice-initiated) form, pattern was: "+script+", first pattern symbol was: "+symbols[0]);
      }
   }

   private void ensurePublicKeysOnce() {
      Map<String, Integer> initiatorSymbolCount = new HashMap<>();
      Map<String, Integer> responderSymbolCount = new HashMap<>();
      for (String scriptLine: script) {
         String[] symbols = scriptLine.substring(3).split(", ");
         String arrow = scriptLine.substring(0, 2);
         for (String symbol: symbols) {
            if (symbol.length() == 1) {
               if (arrow.equals("->")) {
                  int count = initiatorSymbolCount.merge(symbol, 1, Integer::sum);
                  if (count > 1) {
                     throw new IllegalArgumentException("script '"+script+"' contained more than 1 '"+symbol+"' initiator symbol");
                  }
               } else {
                  int count = responderSymbolCount.merge(symbol, 1, Integer::sum);
                  if (count > 1) {
                     throw new IllegalArgumentException("script '"+script+"' contained more than 1 '"+symbol+"' responder symbol");
                  }
               }
            }
         }
      }
   }

   private void ensureNegotiationsOnce() {
      Map<String, Integer> symbolCount = new HashMap<>();
      for (String scriptLine: script) {
         String[] symbols = scriptLine.substring(3).split(", ");
         for (String symbol: symbols) {
            if (symbol.length() == 2) {
               int count = symbolCount.merge(symbol, 1, Integer::sum);
               if (count > 1) {
                  throw new IllegalArgumentException("script '"+script+"' contained more than 1 '"+symbol+"' symbol");
               }
            }
         }
      }
   }

   public static final class Execution {
      private final List<String> script;
      private final boolean machineInitiator;
      private int line = 0;

      private Execution(List<String> script, boolean machineInitiator, int line) {
         this.script = script;
         this.machineInitiator = machineInitiator;
         this.line = line;
      }

      private Execution(List<String> script, boolean machineInitiator) {
         this(script, machineInitiator, 0);
      }

      public Execution nextLineForLocal(PatternMachine machine) {
         return nextLine(machine, true);
      }

      public Execution nextLineForRemote(PatternMachine machine) {
         return nextLine(machine, false);
      }

      /**
       * Run the next line of the execution.
       */
      private Execution nextLine(PatternMachine machine, boolean forLocal) {
         if (line < script.size() && script.get(line).equals("...")) {
            line++; // Skip "..."
         }
         if (line >= script.size()) {
            throw new IllegalStateException("pattern already ended, channel should be already established");
         }
         if (!isPreMessage() && (forLocal != isLocal())) {
            throw new IllegalStateException("wanted to execute for "+(forLocal?"for local":"for remote")+", but was the other's turn, current line is: "+script.get(line));
         }
         for (String symbol: script.get(line).substring(3).split(", ")) {
            switch (symbol) {
               case "e":
                  if (isLocal()) {
                     machine.localSendsEphemeralKey();
                  } else {
                     machine.remoteSendsEphemeralKey();
                  }
                  break;
               case "s":
                  if (isLocal()) {
                     if (isPreMessage()) {
                        machine.localStaticKeyPreMessage();
                     } else {
                        machine.localSendsStaticKey();
                     }
                  } else {
                     if (isPreMessage()) {
                        machine.remoteStaticKeyPreMessage();
                     } else {
                        machine.remoteSendsStaticKey();
                     }
                  }
                  break;
               case "ee":
                  machine.negotiateEphemeralKeys();
                  break;
               case "es":
                  if (isLocal()) {
                     machine.negotiateLocalEphemeralWithRemoteStaticKey();
                  } else {
                     machine.negotiateLocalStaticWithRemoteEphemeralKey();
                  }
                  break;
               case "se":
                  if (isLocal()) {
                     machine.negotiateLocalStaticWithRemoteEphemeralKey();
                  } else {
                     machine.negotiateLocalEphemeralWithRemoteStaticKey();
                  }
                  break;
               case "ss":
                  machine.negotiateStaticKeys();
                  break;
               default:
                  throw new IllegalArgumentException("encountered unhandled symbol: "+symbol);
            }
         }
         line++;
         if (line >= script.size()) {
            machine.establish();
         }
         if (isPreMessage()) {
            // Recurse all pre-messages
            nextLine(machine, forLocal);
         }
         return this;
      }

      private boolean isPreMessage() {
         return script.subList(line, script.size()).contains("...");
      }

      private boolean isLocal() {
         return
            (isSymbolInitiator() && machineInitiator) ||
            (!isSymbolInitiator() && !machineInitiator);
      }
      
      private boolean isSymbolInitiator() {
         return script.get(line).startsWith("-> ");
      }

      public static Serdes<Execution> serdes(Pattern pattern) {
         return seq(
            booleanSerdes(),
            independent(intSerdes()))
            .map((e) -> tuple(e.machineInitiator, e.line),
                 tuple -> new Execution(pattern.script, tuple.a, tuple.b));
      }
   }
}

