package com.example.crypto;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class Secp256k1Util {
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(),
            CURVE_PARAMS.getG(),
            CURVE_PARAMS.getN(),
            CURVE_PARAMS.getH()
    );

    // 16진수 문자열을 바이트 배열로 변환
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // 바이트 배열을 16진수 문자열로 변환
    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // 키 쌍 생성
    public static void generateKeyPair(StringBuffer hpub, StringBuffer hpri) throws Exception {
        // 안전한 난수 생성
        SecureRandom secureRandom = new SecureRandom();
        byte[] privateKeyBytes = new byte[32];
        secureRandom.nextBytes(privateKeyBytes);
        
        // private key의 범위를 curve의 order 내로 제한
        BigInteger privateKey = new BigInteger(1, privateKeyBytes);
        privateKey = privateKey.mod(CURVE.getN());
        
        // private key를 32바이트로 패딩
        byte[] paddedPrivateKey = new byte[32];
        byte[] privateKeyModBytes = privateKey.toByteArray();
        System.arraycopy(
            privateKeyModBytes, 
            Math.max(0, privateKeyModBytes.length - 32), 
            paddedPrivateKey, 
            Math.max(0, 32 - privateKeyModBytes.length), 
            Math.min(32, privateKeyModBytes.length)
        );
        
        // public key 생성 (33 bytes, compressed format)
        ECPoint publicKeyPoint = CURVE.getG().multiply(privateKey);
        byte[] publicKeyBytes = publicKeyPoint.getEncoded(true);  // true = compressed format

        hpri.append(byteArrayToHexString(paddedPrivateKey));
        hpub.append(byteArrayToHexString(publicKeyBytes));
    }

    // 서명 생성
    public static String sign(String message, String privateKeyHex) throws Exception {
        byte[] privateKeyBytes = hexStringToByteArray(privateKeyHex);
        byte[] messageBytes = message.getBytes();

        // SHA-256 해시 계산
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = digest.digest(messageBytes);

        // ECDSA 서명 생성
        ECDSASigner signer = new ECDSASigner();
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), CURVE);
        signer.init(true, privKey);
        BigInteger[] signature = signer.generateSignature(messageHash);

        // R|S 형식으로 서명값 연결
        byte[] r = signature[0].toByteArray();
        byte[] s = signature[1].toByteArray();
        
        // r, s 각각 32바이트로 패딩
        byte[] paddedR = new byte[32];
        byte[] paddedS = new byte[32];
        System.arraycopy(r, Math.max(0, r.length - 32), paddedR, Math.max(0, 32 - r.length), Math.min(32, r.length));
        System.arraycopy(s, Math.max(0, s.length - 32), paddedS, Math.max(0, 32 - s.length), Math.min(32, s.length));

        // 최종 서명값 생성 (64바이트)
        byte[] signatureBytes = new byte[64];
        System.arraycopy(paddedR, 0, signatureBytes, 0, 32);
        System.arraycopy(paddedS, 0, signatureBytes, 32, 32);

        return byteArrayToHexString(signatureBytes);
    }

    // 서명 검증
    public static boolean verify(String message, String signatureHex, String publicKeyHex) throws Exception {
        byte[] publicKeyBytes = hexStringToByteArray(publicKeyHex);
        byte[] signatureBytes = hexStringToByteArray(signatureHex);
        byte[] messageBytes = message.getBytes();

        // 메시지 해시 계산
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = digest.digest(messageBytes);

        // 서명값 분리 (R|S)
        byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
        byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);

        // 공개키 포인트 복원
        ECPoint pubPoint = CURVE.getCurve().decodePoint(publicKeyBytes);

        // 서명 검증
        ECDSASigner verifier = new ECDSASigner();
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(pubPoint, CURVE);
        verifier.init(false, pubKey);

        return verifier.verifySignature(messageHash, new BigInteger(1, r), new BigInteger(1, s));
    }

    

        // 내부 헬퍼 메소드들...
        private static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        }
    
        private static byte[] hexToBytes(String hex) {
            int len = hex.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                   + Character.digit(hex.charAt(i+1), 16));
            }
            return data;
        }

    public static void main(String[] args) {
        try {
            System.out.println("Secp256k1Util");
            // 키 쌍 생성 테스트
            StringBuffer publicKey = new StringBuffer();
            StringBuffer privateKey = new StringBuffer();
            generateKeyPair(publicKey, privateKey);
            
            System.out.println("Private Key: " + privateKey.toString() + " (length: " + privateKey.length() + ")");
            System.out.println("Public Key: " + publicKey.toString() + " (length: " + publicKey.length() + ")");

            // 서명 생성 테스트
            String message = "Hello, World!";
            String signature = sign(message, privateKey.toString());
            System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");

            // 서명 검증 테스트
            boolean isValid = verify(message, signature, publicKey.toString());
            System.out.println("Signature Valid: " + isValid);

            // 잘못된 메시지로 검증 테스트
            boolean isInvalid = verify("Wrong message", signature, publicKey.toString());
            System.out.println("Invalid Signature Test: " + isInvalid);




            
            //////////////////////////////////////////////////////////////////////////////////
            // test2
            publicKey.setLength(0);
            privateKey.setLength(0);
            publicKey.append("03b52244777339044642b540520a855445f21a8835152744f022960b5e8e16c278");
            privateKey.append("6700a4648f9fdc68f98d262a75e91be2c0e746e3328d606d854330d3e6c9ea6a");

            // message
            message = "Uap3XXAVpoaJShJNVOJC";
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes());
            String messageHash = bytesToHex(hash).toLowerCase();
            System.out.println("Message: " + message);

            signature = sign(message, privateKey.toString());
            System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");
            isValid = verify(message, signature, publicKey.toString());
            System.out.println("Signature Valid: " + isValid);


            System.out.println("Message Hash: " + messageHash);
    
            signature = sign(messageHash, privateKey.toString());
            System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");
            // e8f33081301d6f0010503eeba669955aae4822eebfc95502236e9d0221b63aa47730c361c8a02678d14055b16cf4e2c8d02b80c7321024ad8876841b7b73f6d5
            // 3e2e4d145eed8bdf93abf03264791e422993381e4d1c671ee50eae2746c3dc5b2445507d8ef320cf16011717ae14980fc8055e08827b34ba8c12c971f62d17d9
            isValid = verify(message, signature, publicKey.toString());
            System.out.println("Signature Valid: " + isValid);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
} 