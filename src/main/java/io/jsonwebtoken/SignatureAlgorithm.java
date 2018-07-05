package io.jsonwebtoken;

import io.jsonwebtoken.impl.crypto.SignatureValidator;
import io.jsonwebtoken.impl.crypto.Signer;

public interface SignatureAlgorithm extends Signer, SignatureValidator {
}
