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

public class Secp256r1Util {
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256r1");
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // private key (32 bytes)
        byte[] privateKeyBytes = ((PrivateKey) keyPair.getPrivate()).getEncoded();
        byte[] rawPrivateKey = Arrays.copyOfRange(privateKeyBytes, privateKeyBytes.length - 32, privateKeyBytes.length);
        
        // public key (33 bytes, compressed format)
        ECPoint q = CURVE.getG().multiply(new BigInteger(1, rawPrivateKey));
        byte[] publicKeyBytes = q.getEncoded(true);  // true = compressed format

        hpri.append(byteArrayToHexString(rawPrivateKey));
        hpub.append(byteArrayToHexString(publicKeyBytes));
    }

    // 서명 생성
    public static String sign(String message, String privateKeyHex) throws Exception {

        byte[] privateKeyBytes = hexStringToByteArray(privateKeyHex);
        byte[] messageBytes = message.getBytes("UTF-8");

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
        byte[] messageBytes = message.getBytes("UTF-8");

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
            System.out.println("Secp256r1Util");
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
  
            System.out.println("--------------------------------");
            System.out.println("Private Key: " + privateKey.toString() + " (length: " + privateKey.length() + ")");
            System.out.println("Public Key: " + publicKey.toString() + " (length: " + publicKey.length() + ")");

            // message
            message = "TEST-qDIWUzzIj2LfOLuD42A2";
            System.out.println("Message: " + message);
            // 이 모듈은 sha256 해시를 할 필요없음. sign 내부에서 처리함. 

            // 서명할 때 마다 값이 달라진다!!! 
            signature = sign(message, privateKey.toString());
            System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");
            isValid = verify(message, signature, publicKey.toString());
            System.out.println("Signature Valid: " + isValid);

            signature = sign(message, privateKey.toString());
            System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");
            isValid = verify(message, signature, publicKey.toString());
            System.out.println("Signature Valid: " + isValid);

            // 서명값을 변경해서 검증 테스트. 
            signature="ae31bcff29ae91868d4f3d1298be9e2aa163df7fe299c5e2fd7a5b2067b5fa29a0517be1c6990bcb7bf09e4a0baf6414108afb50859c6af37b0d0912120f494d" ;
            System.out.println("signature change to:"+signature);

            isValid = verify(message, signature, publicKey.toString());
            System.out.println("Signature Valid: " + isValid);
            System.out.println("--------------------------------");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
} 