package com.example;import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESUtil {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    // AES256 . 32 bytes
    private static final String KEY_STRING = "12345678901234567890123456789012";
    // 키와 IV 생성
    private static SecretKeySpec getKey() {
        byte[] keyBytes = KEY_STRING.getBytes();
        return new SecretKeySpec(keyBytes, "AES");
    }
    
    private static IvParameterSpec getIV() {
        byte[] keyBytes = KEY_STRING.getBytes();
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyBytes, 0, ivBytes, 0, 16);
        return new IvParameterSpec(ivBytes);
    }

    /**
     * AES 암호화
     * @param plainText 암호화할 문자열
     * @return Base64로 인코딩된 암호화 문자열
     */
    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getKey(), getIV());
        
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * AES 복호화
     * @param encryptedText Base64로 인코딩된 암호화 문자열
     * @return 복호화된 문자열
     */
    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getKey(), getIV());
        
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(original);
    }

    /*
javac -encoding UTF-8 AESUtil.java
java AESUtil

     */

    public static void main(String[] args) {
        try {
            String plainText = "Hello, World!";

            String encText = AESUtil.encrypt(plainText);
            System.out.println("encText: " + encText);
            String decText = AESUtil.decrypt(encText);
            System.out.println("decText: " + decText);
                        
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

} 

