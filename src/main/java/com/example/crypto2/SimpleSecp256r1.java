//package com.secuve.secusignec.util ;
package com.example.crypto2;

import java.security.MessageDigest;
/*
 * SECP256R1 암호화 라이브러리
 */

public class SimpleSecp256r1 {
	/*
	native public static String version();
	/// ecdsa
	// 키쌍 생성
	// 리턴결과 pub, pri =hexa string.
	// pub length = (32+1)*2, pri lenght=32 *2
	native public boolean ecdsa_make_key(StringBuffer hpub, StringBuffer hpri) throws Exception;

	// hpri ; private key. hexa string format
	// hsha256hash ; 서명할 데이터의 sha256 해시. hexa string format
	native public boolean ecdsa_sign(String hpri, String hsha256hash, StringBuffer hsignature) throws Exception;
	native public boolean ecdsa_verify(String hpub, String hsha256hash, String hsignature) throws Exception;
		
    static {
            System.loadLibrary("simplecryptjni");
    }
    */
	public static String version() {
		return "0.1.2" ;
	}
	public boolean ecdsa_make_key(StringBuffer hpub, StringBuffer hpri) {
		byte[] p_publicKey = new byte[ECC.ECC_BYTES+1] ;
		byte[] p_privateKey = new byte[ECC.ECC_BYTES];
		boolean bret = false ;
		
		bret = ECC.ecc_make_key(p_publicKey, p_privateKey) ;
		if ( bret ) {
			hpub.append(ECC.byteArrayToHexString(p_publicKey)) ;
			hpri.append(ECC.byteArrayToHexString(p_privateKey));
		}
		return bret ;
	}

	// hpri ; private key. hexa string format
	// hsha256hash ; 서명할 데이터의 sha256 해시. hexa string format
	public boolean ecdsa_sign(String hpri, String hsha256hash, StringBuffer hsignature) {
		byte[] p_privateKey = ECC.hexStringToByteArray(hpri) ;
		byte[] p_hash = ECC.hexStringToByteArray(hsha256hash) ;
		byte[] p_signature = new byte[ECC.ECC_BYTES*2] ;

		ECC.ecdsa_sign(p_privateKey, p_hash, p_signature) ;
		hsignature.append(ECC.byteArrayToHexString(p_signature));
		
		return true ;
	}
	
	public boolean ecdsa_verify(String hpub, String hsha256hash, String hsignature) {
		byte[] p_publicKey = ECC.hexStringToByteArray(hpub) ;
		byte[] p_hash = ECC.hexStringToByteArray(hsha256hash) ;
		byte[] p_signature = ECC.hexStringToByteArray(hsignature);

		return ECC.ecdsa_verify(p_publicKey, p_hash, p_signature) ;
	}
	
	public boolean ecdsa_make_sharedkey(String hpubpeer, String hpri, StringBuffer hsharedkey) {
		byte[] p_publicKey = ECC.hexStringToByteArray(hpubpeer) ;
		byte[] p_privateKey = ECC.hexStringToByteArray(hpri) ;
		byte[] p_secret = new byte[ECC.ECC_BYTES] ;
		boolean bret = false ;
		
		bret = ECC.ecdh_shared_secret(p_publicKey, p_privateKey, p_secret) ;
		hsharedkey.append( ECC.byteArrayToHexString(p_secret)) ;
		
		return bret ;
	}
	

	
}

class testSimpleSecp256r1 {
    // 헬퍼 메소들을 static final로 선언하여 성능 향상
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || (hex.length() % 2) == 1)
            throw new IllegalArgumentException();
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                               + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    // KeyPair 클래스 제거 - 원래 코드대로 진행
    public static void main(String[] arg) throws Exception {
			boolean isValid = false ;
                System.out.println("JAVA:call native") ;

				System.out.println("call simplecrypt.version()");
				String ver = SimpleSecp256r1.version() ; // api
				System.out.println("ver="+ver) ;

                SimpleSecp256r1 t = new SimpleSecp256r1() ;
				
				// make key
				StringBuffer hpub = new StringBuffer("") ;
				StringBuffer hpri = new StringBuffer("") ;
                boolean bret = t.ecdsa_make_key(hpub, hpri) ;
				System.out.println("ecdsa_make_key()");
				System.out.println(" hpub="+hpub.toString()) ;
				System.out.println(" hpri="+hpri.toString()) ;

				
				StringBuffer hpub2 = new StringBuffer("") ;
				StringBuffer hpri2 = new StringBuffer("") ;
                bret = t.ecdsa_make_key(hpub2, hpri2) ;
				System.out.println("ecdsa_make_key()");
				System.out.println(" hpub2="+hpub2.toString()) ;
				System.out.println(" hpri2="+hpri2.toString()) ;
				
				// shared key
				StringBuffer hsharedkey = new StringBuffer() ;
				bret = t.ecdsa_make_sharedkey(hpub.toString(), hpri2.toString(), hsharedkey) ;
				System.out.println("shared key1="+hsharedkey.toString());

				StringBuffer hsharedkey2 = new StringBuffer() ;
				bret = t.ecdsa_make_sharedkey(hpub2.toString(), hpri.toString(), hsharedkey2) ;
				System.out.println("shared key2="+hsharedkey2.toString());

				// sign
				String orgmsg = "hello world!" ;
				String hsha256hash = "aa792742fb7e39293514ebbe503c7b2ae3bf28f3c3bdcf5ad61afa447d5afb53";
				
				byte[] bhash = ECC.sha256(orgmsg.getBytes("UTF-8")) ;
				hsha256hash = ECC.byteArrayToHexString(bhash) ;	// generated sha256 use..
				
				StringBuffer hsignature = new StringBuffer("") ;
				System.out.println("ecdsa_sign()");
				bret = t.ecdsa_sign(hpri.toString(), hsha256hash, hsignature) ;
				System.out.println(" hash="+hsha256hash);
				System.out.println(" hsignature="+hsignature.toString()) ;

				// verify
				System.out.println("ecdsa_verify()");
				bret = t.ecdsa_verify(hpub.toString(), "00"+hsha256hash, hsignature.toString()) ;
				System.out.println(" verify fail test result="+bret) ;
				bret = t.ecdsa_verify(hpub.toString(), hsha256hash, hsignature.toString()) ;
				System.out.println(" verify ok test result="+bret) ;

				//////////////////////////test
				System.out.println("--------------------------------");
				StringBuffer publicKey = new StringBuffer("") ;
				StringBuffer privateKey = new StringBuffer("") ;

				publicKey.append("03b52244777339044642b540520a855445f21a8835152744f022960b5e8e16c278");
				privateKey.append("6700a4648f9fdc68f98d262a75e91be2c0e746e3328d606d854330d3e6c9ea6a");
				System.out.println("Private Key: " + privateKey.toString() + " (length: " + privateKey.length() + ")");
				System.out.println("Public Key: " + publicKey.toString() + " (length: " + publicKey.length() + ")");
	
				// message
				String message = "TEST-qDIWUzzIj2LfOLuD42A2";
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] hash = digest.digest(message.getBytes("UTF-8"));
				String messageHash = bytesToHex(hash).toLowerCase();
				System.out.println("Message: " + message);
				System.out.println("Message Hash: " + messageHash);

				// 이 모듈에서는 위와 같이 수동으로 sha256 해줘야 함.

				// 아래는 서명해서 서명값을 출력. 동일한 데이터에 서명을 해도 서명값은 매 번 달라진다!!! Warning...
				hsignature.setLength(0);
				t.ecdsa_sign(privateKey.toString(), messageHash, hsignature) ;
				String signature = hsignature.toString() ;
				System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");
				isValid = t.ecdsa_verify(publicKey.toString(), messageHash, signature);
				System.out.println("Signature Valid: " + isValid);

				hsignature.setLength(0);
				t.ecdsa_sign(privateKey.toString(), messageHash, hsignature) ;
				signature = hsignature.toString() ;
				System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");
				isValid = t.ecdsa_verify(publicKey.toString(), messageHash, signature);
				System.out.println("Signature Valid: " + isValid);

				hsignature.setLength(0);
				t.ecdsa_sign(privateKey.toString(), messageHash, hsignature) ;
				signature = hsignature.toString() ;
				System.out.println("Signature: " + signature + " (length: " + signature.length() + ")");
				isValid = t.ecdsa_verify(publicKey.toString(), messageHash, signature);
				System.out.println("Signature Valid: " + isValid);

				// 아래는 서명값을 변경해서 검증 테스트. 
				signature="ae31bcff29ae91868d4f3d1298be9e2aa163df7fe299c5e2fd7a5b2067b5fa29a0517be1c6990bcb7bf09e4a0baf6414108afb50859c6af37b0d0912120f494d" ;
				System.out.println("signature change to:"+signature);

				isValid = t.ecdsa_verify(publicKey.toString(), messageHash, signature);
				System.out.println("Signature Valid: " + isValid);
				System.out.println("--------------------------------");

				// 검증 실패 테스트. 
				signature="ffffbcff29ae91868d4f3d1298be9e2aa163df7fe299c5e2fd7a5b2067b5fa29a0517be1c6990bcb7bf09e4a0baf6414108afb50859c6af37b0d0912120f494d" ;
				System.out.println("signature change to:"+signature);
				isValid = t.ecdsa_verify(publicKey.toString(), messageHash, signature);
				System.out.println("Signature verify fail: " + isValid);
				System.out.println("--------------------------------");
	
        }
        
}
