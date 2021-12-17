/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.pattern;

import static java.util.Arrays.asList;

public final class Fundamentals {
   public static final Pattern NN = Pattern.of("NN", asList(
         "-> e",
         "<- e, ee"
   ));

   public static final Pattern KK = Pattern.of("KK", asList(
         "-> s",
         "<- s",
         "...",
         "-> e, es, ss",
         "<- e, ee, se"
   ));

   private Fundamentals() {
   }
}
