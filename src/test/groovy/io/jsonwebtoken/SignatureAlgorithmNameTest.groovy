/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken

import org.junit.Test
import static org.junit.Assert.*

class SignatureAlgorithmNameTest {

    @Test
    void testNames() {
        def algNames = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
                        'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'NONE']

        for( String name : algNames ) {
            testName(name)
        }
    }

    private static void testName(String name) {
        def alg = SignatureAlgorithmName.forName(name);
        def namedAlg = name as SignatureAlgorithmName //Groovy type coercion FTW!
        assertTrue alg == namedAlg
        assert alg.description != null && alg.description != ""
    }

    @Test(expected = SignatureException)
    void testUnrecognizedAlgorithmName() {
        SignatureAlgorithmName.forName('whatever')
    }

    @Test
    void testIsHmac() {
        for(SignatureAlgorithmName alg : SignatureAlgorithmName.values()) {
            if (alg.name().startsWith("HS")) {
                assertTrue alg.isHmac()
            } else {
                assertFalse alg.isHmac()
            }
        }
    }

    @Test
    void testHmacFamilyName() {
        for(SignatureAlgorithmName alg : SignatureAlgorithmName.values()) {
            if (alg.name().startsWith("HS")) {
                assertEquals alg.getFamilyName(), "HMAC"
            }
        }
    }

    @Test
    void testIsRsa() {
        for(SignatureAlgorithmName alg : SignatureAlgorithmName.values()) {
            if (alg.getDescription().startsWith("RSASSA")) {
                assertTrue alg.isRsa()
            } else {
                assertFalse alg.isRsa()
            }
        }
    }

    @Test
    void testRsaFamilyName() {
        for(SignatureAlgorithmName alg : SignatureAlgorithmName.values()) {
            if (alg.name().startsWith("RS") || alg.name().startsWith("PS")) {
                assertEquals alg.getFamilyName(), "RSA"
            }
        }
    }

    @Test
    void testIsEllipticCurve() {
        for(SignatureAlgorithmName alg : SignatureAlgorithmName.values()) {
            if (alg.name().startsWith("ES")) {
                assertTrue alg.isEllipticCurve()
            } else {
                assertFalse alg.isEllipticCurve()
            }
        }
    }

    @Test
    void testEllipticCurveFamilyName() {
        for(SignatureAlgorithmName alg : SignatureAlgorithmName.values()) {
            if (alg.name().startsWith("ES")) {
                assertEquals alg.getFamilyName(), "Elliptic Curve"
            }
        }
    }

    @Test
    void testIsJdkStandard() {
        for(SignatureAlgorithmName alg : SignatureAlgorithmName.values()) {
            if (alg.name().startsWith("ES") || alg.name().startsWith("PS") || alg == SignatureAlgorithmName.NONE) {
                assertFalse alg.isJdkStandard()
            } else {
                assertTrue alg.isJdkStandard()
            }
        }
    }
}
