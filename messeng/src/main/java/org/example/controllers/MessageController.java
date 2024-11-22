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
    private SecretKey aesKey;
    private KeyPair rsaKeyPair;
    private String lastMessange;
    private String lastMethodForLastMessange;
    private PublicKey lastKey;
    private String caesarKey;

    @PostMapping("/accept_messange")
    public void acceptMessange(@RequestBody EncryptedMessage encryptedMessage){
        this.lastMessange = encryptedMessage.getMessage();
        this.lastMethodForLastMessange = encryptedMessage.getMethod();
    }

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody EncryptedMessage message) throws Exception {
        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                return encryptionService.encryptCaesar(message.getMessage(), Integer.parseInt(this.caesarKey));
            case "aes":
                return encryptionService.encryptAES(message.getMessage(), this.aesKey);
            case "rsa":
                return encryptionService.encryptRSA(message.getMessage(), this.lastKey);
            default:
                throw new IllegalArgumentException("Invalid method");
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody EncryptedMessage message) throws Exception {
        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                return encryptionService.decryptCaesar(message.getMessage(), Integer.parseInt(this.caesarKey));
            case "aes":
                return encryptionService.decryptAES(message.getMessage(), this.aesKey);
            case "rsa":
                return encryptionService.decryptRSA(message.getMessage(), rsaKeyPair.getPrivate());
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
                rsaKeyPair = keyService.generateRSAKeyPair();
                return "RSA ключ сгенерирован";
            case "caesar":
                Random random = new Random();
                int randomNumber = random.nextInt(100);
                caesarKey = Integer.toString(randomNumber);
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
            byte[] keyBytes = rsaKeyPair.getPublic().getEncoded();
            encryptedMessage.setKey(Base64.getEncoder().encodeToString(keyBytes));
        } else if ("aes".equalsIgnoreCase(method)){
            byte[] keyBytes = aesKey.getEncoded();
            encryptedMessage.setKey(Base64.getEncoder().encodeToString(keyBytes));
        } else if ("caesar".equalsIgnoreCase(method)){
            encryptedMessage.setKey(this.caesarKey);
        }
        sendClien.getPublicKey(encryptedMessage);
    }

    @PostMapping("/get_public_key")
    public void getPublicKey(@RequestBody SendKey encryptedMessage) throws Exception {
        if ("rsa".equalsIgnoreCase(encryptedMessage.getMethod())) {
            byte[] keyBytes = Base64.getDecoder().decode(encryptedMessage.getKey());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.lastKey = keyFactory.generatePublic(spec);
        } else if ("aes".equalsIgnoreCase(encryptedMessage.getMethod())){
            byte[] keyBytes = Base64.getDecoder().decode(encryptedMessage.getKey());
            this.aesKey = new SecretKeySpec(keyBytes, "AES");
            encryptedMessage.setKey(Base64.getEncoder().encodeToString(keyBytes));
        } else if ("caesar".equalsIgnoreCase(encryptedMessage.getMethod())){
            this.caesarKey = encryptedMessage.getKey();
        }
    }
}
