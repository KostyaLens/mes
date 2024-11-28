package org.example.controllers;


import lombok.RequiredArgsConstructor;
import org.example.client.SendClient;
import org.example.model.EncryptedMessage;
import org.example.model.SendKey;
import org.example.services.EncryptionService;
import org.example.services.KeyService;
import org.springframework.web.bind.annotation.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MessageController {

    private final EncryptionService encryptionService;
    private final KeyService keyService;
    private final SendClient sendClien;
    private byte[] aesKey;
    private String lastMessange;
    private String lastMethodForLastMessange;
    private int caesarKey = 0;

    @PostMapping("/accept_messange")
    public void acceptMessange(@RequestBody EncryptedMessage encryptedMessage){
        this.lastMessange = encryptedMessage.getMessage();
        this.lastMethodForLastMessange = encryptedMessage.getMethod();
    }

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody EncryptedMessage message) throws Exception {
        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                if (this.caesarKey == 0){
                    return "У вас нет ключа";
                }
                return encryptionService.encryptCaesar(message.getMessage(), this.caesarKey);
            case "aes":
                if (this.aesKey.length == 0){
                    return "У вас нет ключа";
                }
                return encryptionService.aesEncrypt(message.getMessage(), this.aesKey);
            case "rsa":
                if (this.publicKey.equals(0)){
                    return "У вас нет ключа";
                }
                return encryptionService.rsaEncrypt(message.getMessage(), this.publicKey, this.modulus);
            default:
                throw new IllegalArgumentException("Invalid method");
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody EncryptedMessage message) throws Exception {
        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                if (this.caesarKey == 0){
                    return "У вас нет ключа";
                }
                return encryptionService.decryptCaesar(message.getMessage(), this.caesarKey);
            case "aes":
                if (this.aesKey.length == 0){
                    return "У вас нет ключа";
                }
                return encryptionService.aesDecrypt(message.getMessage(), this.aesKey);
            case "rsa":
                if (this.publicKey.equals(0)){
                    return "У вас нет ключа";
                }
                return encryptionService.rsaDecrypt(message.getMessage(), this.privateKey, this.modulus);
            default:
                throw new IllegalArgumentException("Invalid method");
        }
    }

    @PostMapping("/encrypt_and_send")
    public String encryptAndSend(@RequestBody EncryptedMessage message) throws Exception {
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setMessage(encrypt(message));
        encryptedMessage.setMethod(message.getMethod());
        sendClien.acceptMessange(encryptedMessage);
        return "Сообщение отправлено, в зашифрованном виде оно такое: " + encryptedMessage.getMessage();
    }

    @PostMapping("/send_encrypted_msg")
    public String sendEncryptedMessage(@RequestBody EncryptedMessage message) {
        sendClien.acceptMessange(message);
        return "Сообщение отправлено";
    }

    @GetMapping("/get_encrypted_msg")
    public String getEncryptedMessage(@RequestParam EncryptedMessage message) throws Exception {
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setMessage(message.getMessage());
        encryptedMessage.setMethod(message.getMethod());
        return decrypt(encryptedMessage);
    }

    @GetMapping("/get_encrypted_msg_last_messnge")
    public String getEncryptedLastMessenge() throws Exception {
        if (this.lastMessange == null) {
            throw new IllegalStateException("No message received.");
        }
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setMessage(this.lastMessange);
        encryptedMessage.setMethod(this.lastMethodForLastMessange);
        return decrypt(encryptedMessage);
    }



    @PostMapping("/generate")
    public String generateKeys(@RequestParam String method) throws Exception {
        switch (method.toLowerCase()) {
            case "aes":
                aesKey = keyService.generateAESKey();
                return "AES ключ сгенерирован";
            case "rsa":
                generateRSAKeys();
                return "RSA ключ сгенерирован";
            case "caesar":
                Random random = new Random();
                int randomNumber = random.nextInt(100);
                caesarKey = randomNumber;
                return "caesar ключ сгенерирован";
            default:
                throw new IllegalArgumentException("Invalid method");
        }
    }

    @PostMapping("/send_public_key")
    public void sendPublicKey(@RequestParam String method) {
        SendKey encryptedMessage = new SendKey();
        encryptedMessage.setMethod(method);
        if ("rsa".equalsIgnoreCase(method)) {
            encryptedMessage.setA(publicKey);
            encryptedMessage.setM(modulus);
        } else if ("aes".equalsIgnoreCase(method)){
            encryptedMessage.setKey(this.aesKey);
        } else if ("caesar".equalsIgnoreCase(method)){
            encryptedMessage.setC(this.caesarKey);
        }
        sendClien.getPublicKey(encryptedMessage);
    }

    @PostMapping("/get_public_key")
    public void getPublicKey(@RequestBody SendKey encryptedMessage) throws Exception {
        if ("rsa".equalsIgnoreCase(encryptedMessage.getMethod())) {
            this.publicKey = encryptedMessage.getA();
            this.modulus = encryptedMessage.getM();
        } else if ("aes".equalsIgnoreCase(encryptedMessage.getMethod())){
            this.aesKey = encryptedMessage.getKey();
        } else if ("caesar".equalsIgnoreCase(encryptedMessage.getMethod())){
            this.caesarKey = encryptedMessage.getC();
        }
    }

    private BigInteger publicKey;
    private BigInteger privateKey;
    private BigInteger modulus;

    public void generateRSAKeys() {
        SecureRandom random = new SecureRandom();
        int bitLength = 1024;
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        modulus = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        publicKey = BigInteger.valueOf(65537);
        if (!phi.gcd(publicKey).equals(BigInteger.ONE)) {
            publicKey = BigInteger.probablePrime(bitLength / 2, random);
        }

        privateKey = publicKey.modInverse(phi);
    }

}
