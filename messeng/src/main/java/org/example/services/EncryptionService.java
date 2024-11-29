package org.example.services;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

@Service
public class EncryptionService {


    public String encryptCaesar(String message, int shift) {
        StringBuilder encrypted = new StringBuilder();
        for (char c : message.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                encrypted.append((char) ((c - base + shift) % 26 + base));
            } else {
                encrypted.append(c);
            }
        }
        return encrypted.toString();
    }

    public String decryptCaesar(String encryptedMessage, int shift) {
        return encryptCaesar(encryptedMessage, 26 - shift);
    }


    public String aesEncrypt(String message, byte[] key) {
        byte[] encrypted = new byte[message.length()];
        for (int i = 0; i < message.length(); i++) {
            encrypted[i] = (byte) (message.charAt(i) ^ key[i % key.length]);
        }
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String aesDecrypt(String encryptedMessage, byte[] key) {
        byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
        char[] decrypted = new char[decoded.length];
        for (int i = 0; i < decoded.length; i++) {
            decrypted[i] = (char) (decoded[i] ^ key[i % key.length]);
        }
        return new String(decrypted);
    }


    public String rsaEncrypt(String message, BigInteger publicKey, BigInteger modulus) {
        BigInteger messageInt = new BigInteger(message.getBytes());
        if (messageInt.compareTo(modulus) >= 0) {
            throw new IllegalArgumentException("Message is too large for the current modulus.");
        }
        BigInteger encrypted = messageInt.modPow(publicKey, modulus);
        return encrypted.toString();
    }

    public String rsaDecrypt(String message, BigInteger privateKey, BigInteger modulus) {
        BigInteger encryptedInt = new BigInteger(message);
        BigInteger decryptedInt = encryptedInt.modPow(privateKey, modulus);
        return new String(decryptedInt.toByteArray());
    }
}