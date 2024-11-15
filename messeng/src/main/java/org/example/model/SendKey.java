package org.example.model;

import lombok.Getter;
import lombok.Setter;

import java.security.KeyPair;

@Setter
@Getter
public class SendKey {
    private String method;
    private String key;
}
