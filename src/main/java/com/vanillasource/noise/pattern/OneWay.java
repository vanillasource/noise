/**
 * Copyright (C) 2019 Robert Braeutigam.
 *
 * All rights reserved.
 */

package com.vanillasource.noise.pattern;

import static java.util.Arrays.asList;

public final class OneWay {
   public static final Pattern N = Pattern.of("N", asList(
         "<- s",
         "...",
         "-> e, es"
   ));

   private OneWay() {
   }
}

