package com.quick.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;


@Configuration
public class KeyPairConfig {

    private KeyPair cachedKeyPair;

    @PostConstruct
    public void initKeyPair() throws Exception {
        System.out.println("Initializing KeyPair...");
        cachedKeyPair = loadKeyPairFromKeystore();
        System.out.println("KeyPair initialized successfully");
    }

    @Bean
    public KeyPair keyPair() {
        if (cachedKeyPair == null) {
            throw new IllegalStateException("KeyPair not initialized");
        }
        return cachedKeyPair;
    }

    private KeyPair loadKeyPairFromKeystore() throws Exception {
//        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
//                new ClassPathResource("keystore.jks"),
//                "123456".toCharArray()
//        );
//        return keyStoreKeyFactory.getKeyPair("jwt-key");

        String keystoreLocation = "keystore.jks";
        String keystorePassword = "123456";
        String alias = "jwt-key";
        String keyPassword = "123456";
        Resource resource = new ClassPathResource(keystoreLocation);
        if (!resource.exists()) {
            throw new RuntimeException("Keystore file not found: " + keystoreLocation);
        }

        try (InputStream is = resource.getInputStream()) {
            // 1. 创建KeyStore实例
            KeyStore keyStore = KeyStore.getInstance("JKS");

            // 2. 加载KeyStore
            char[] passwordChars = keystorePassword.toCharArray();
            keyStore.load(is, passwordChars);


            // 4. 获取私钥
            char[] keyPassChars = (keyPassword != null) ?
                    keyPassword.toCharArray() : passwordChars;

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassChars);
            if (privateKey == null) {
                throw new RuntimeException("Private key not found for alias: " + alias);
            }

            // 5. 获取证书和公钥
            Certificate cert = keyStore.getCertificate(alias);
            if (cert == null) {
                throw new RuntimeException("Certificate not found for alias: " + alias);
            }

            PublicKey publicKey = cert.getPublicKey();

            return new KeyPair(publicKey, privateKey);
        }
    }
}
