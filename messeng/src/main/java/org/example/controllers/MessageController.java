package org.example.controllers;

import lombok.RequiredArgsConstructor;
import org.example.client.SendClient;
import org.example.model.EncryptedMessage;
import org.example.model.SendKey;
import org.example.services.EncryptionService;
import org.example.services.KeyService;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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
    private PublicKey lastPublicKey;  // Используем PublicKey для хранения последнего публичного ключа

    @PostMapping("/accept_messange")
    public void acceptMessange(@RequestBody EncryptedMessage encryptedMessage){
        this.lastMessange = encryptedMessage.getMessage();
        this.lastMethodForLastMessange = encryptedMessage.getMethod();
    }

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody EncryptedMessage message) throws Exception {
        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                return encryptionService.encryptCaesar(message.getMessage(), Integer.parseInt(message.getKey()));
            case "aes":
                return encryptionService.encryptAES(message.getMessage(), aesKey);
            case "rsa":
                return encryptionService.encryptRSA(message.getMessage(), lastPublicKey);
            default:
                throw new IllegalArgumentException("Invalid method");
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody EncryptedMessage message) throws Exception {
        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                return encryptionService.decryptCaesar(message.getMessage(), Integer.parseInt(message.getKey()));
            case "aes":
                return encryptionService.decryptAES(message.getMessage(), aesKey);
            case "rsa":
                String cleanMessage = message.getMessage().replaceAll("\\s", "");
                return encryptionService.decryptRSA(cleanMessage, rsaKeyPair.getPrivate());
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
            default:
                throw new IllegalArgumentException("Invalid method");
        }
    }

    @PostMapping("/send_public_key")
    public void sendPublicKey(@RequestParam String method) {
        if ("rsa".equalsIgnoreCase(method)) {
            SendKey encryptedMessage = new SendKey();
            encryptedMessage.setMethod(method);
            encryptedMessage.setKey(Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
            sendClien.getPublicKey(encryptedMessage);
        }
    }

    @PostMapping("/get_public_key")
    public void getPublicKey(@RequestBody SendKey encryptedMessage) throws Exception {
        if ("rsa".equalsIgnoreCase(encryptedMessage.getMethod())) {
            // Декодируем ключ из Base64
            byte[] decodedKey = Base64.getDecoder().decode(encryptedMessage.getKey());

            // Создаем KeyFactory для RSA
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Генерируем публичный ключ из декодированного массива байтов
            lastPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
        }
    }
}
