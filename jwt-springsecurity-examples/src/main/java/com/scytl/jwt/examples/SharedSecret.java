/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 9:14:54 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.examples;

import java.security.SecureRandom;

public class SharedSecret {

    private static byte[] _sharedSecret = new byte[0];

    static {
        SecureRandom random = new SecureRandom();
        _sharedSecret = new byte[32];
        random.nextBytes(_sharedSecret);
    }

    public static final byte[] getSecret() {
        return _sharedSecret;
    }

}
