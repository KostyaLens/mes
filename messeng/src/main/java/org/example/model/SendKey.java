package org.example.model;

import lombok.Getter;
import lombok.Setter;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

@Setter
@Getter
public class SendKey {
    private String method;
    private String key;
}
