package com.example.crypto2;

import java.io.UnsupportedEncodingException;
//import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

//import org.apache.commons.lang3.ArrayUtils;
/*
 * ECC 
 * 
 * porting by crazyj7@gmail.com
 * 
 */

public class ECC {

//	public static final int secp128r1 = 16;
//	public static final int secp192r1 = 24;
	public static final int secp256r1 = 32; // select!!!
//	public static final int secp384r1 = 48;

	// select
	public static final int ECC_CURVE = secp256r1; // 32
	public static final int ECC_BYTES = ECC_CURVE; // 32
	public static final int NUM_ECC_DIGITS = (ECC_BYTES / 8); // 4
	public static final int MAX_TRIES = 16;

	// 자주 사용되는 배열을 재사용하기 위해 ThreadLocal 사용
	private static final ThreadLocal<long[]> tempArray = 
		ThreadLocal.withInitial(() -> new long[NUM_ECC_DIGITS]);

	// StringBuilder 재사용
	private static final ThreadLocal<StringBuilder> hexBuilder = 
		ThreadLocal.withInitial(() -> new StringBuilder(128));
		
	public static String byteArrayToHexString(final byte[] b) {
		StringBuilder sb = hexBuilder.get();
		sb.setLength(0);
		for (byte value : b) {
			String h = Integer.toString(value & 0xff, 16);
			if (h.length() < 2) {
				sb.append('0');
			}
			sb.append(h);
		}
		return sb.toString();
	}

	public static long[] curve_p = { 0xFFFFFFFFFFFFFFFFl, 0x00000000FFFFFFFFl, 0x0000000000000000l,
			0xFFFFFFFF00000001l };
	public static long[] curve_b = { 0x3BCE3C3E27D2604Bl, 0x651D06B0CC53B0F6l, 0xB3EBBD55769886BCl,
			0x5AC635D8AA3A93E7l };

	public static EccPoint curve_G = new EccPoint(0xF4A13945D898C296l, 0x77037D812DEB33A0l, 0xF8BCE6E563A440F2l,
			0x6B17D1F2E12C4247l, 0xCBB6406837BF51F5l, 0x2BCE33576B315ECEl, 0x8EE7EB4A7C0F9E16l, 0x4FE342E2FE1A7F9Bl);

	public static long[] curve_n = { 0xF3B9CAC2FC632551l, 0xBCE6FAADA7179E84l, 0xFFFFFFFFFFFFFFFFl,
			0xFFFFFFFF00000000l };

	public static long[] curve_test = { 0x3BCE3C3E27D2604Bl, 0x651D06B0CC53B0F6l, 0xB3EBBD55769886BCl,
			0x5AC635D8AA3A93E7l };
	public static long[] curve_test2 = { 0xF3B9CAC2FC632551l, 0xBCE6FAADA7179E84l, 0xFFFFFFFFFFFFFFFFl,
			0xFFFFFFFF00000000l };
	
	public static byte[] sha256(byte[] msg) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(msg);
		return md.digest();
	}
	
	// java 1.8 ; Long.compareUnsigned()
	// for java 1.7
	public static int compareUnsigned(long x, long y) {
		   return Long.compare(x + Long.MIN_VALUE, y + Long.MIN_VALUE);
		   // return Long.compareUnsigned(x, y) ; // jdk1.8 
	}

	public static int compareUnsigned(int x, int y) {
		   return Integer.compare(x + Integer.MIN_VALUE, y + Integer.MIN_VALUE);
		   // return Integer.compareUnsigned(x, y) ; // jdk1.8 
	}

	// case insensitive
	public static byte[] hexStringToByteArray(final String s) {
		if (s == null || (s.length() % 2) == 1)
			throw new IllegalArgumentException();
		final char[] chars = s.toCharArray();
		final int len = chars.length;
		final byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(chars[i], 16) << 4) + Character.digit(chars[i + 1], 16));
		}
		return data;
	}

	// return 8 bytes random.
	public static int getRandomNumber(long[] ra) {
		// get 64bit random number ;
		
		Random rand = new Random();
		if (ra != null) {
			for (int i = 0; i < ra.length; i++)
				ra[i] = rand.nextLong();
		}
		
		// debug
		/*
		for (int i = 0; i < ra.length; i++)
			ra[i]=i+1 ;
		*/
		
		return 1;
	}

	public static void vli_clear(long[] p_vli, int i1) {
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			p_vli[i1+i] = 0;
		}
	}
	
	public static void vli_clear(long[] p_vli) {
		vli_clear(p_vli, 0) ;
	}

	/* Returns 1 if p_vli == 0, 0 otherwise. */
	public static boolean vli_isZero(long[] p_vli, int i1) {
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			if (p_vli[i1+i] != 0) {
				return false;
			}
		}
		return true;
	}
	
	public static boolean vli_isZero(long[] p_vli) {
		return vli_isZero(p_vli, 0) ;
	}

	/* Returns nonzero if bit p_bit of p_vli is set. */
	public static long vli_testBit(long[] p_vli, int p_bit) {
		return (p_vli[p_bit / 64] & ((long) 1 << (p_bit % 64)));
	}

	/* Counts the number of 64-bit "digits" in p_vli. */
	public static int vli_numDigits(long[] p_vli, int i1) {
		int i;
		/*
		 * Search from the end until we find a non-zero digit. We do it in reverse
		 * because we expect that most digits will be nonzero.
		 */
		for (i = NUM_ECC_DIGITS - 1; i >= 0 && p_vli[i1+i] == 0; --i) {
		}
		return (i + 1);
	}
	
	public static int vli_numDigits(long[] p_vli) {
		return vli_numDigits(p_vli, 0) ;
	}

	/* Counts the number of bits required for p_vli. */
	public static int vli_numBits(long[] p_vli, int i1) {
		int i;
		long l_digit;

		int l_numDigits = vli_numDigits(p_vli, i1);
		if (l_numDigits == 0) {
			return 0;
		}

		l_digit = p_vli[i1+l_numDigits - 1];
		for (i = 0; l_digit != 0; ++i) {
			l_digit >>>= 1;
		}

		return ((l_numDigits - 1) * 64 + i);
	}
	
	public static int vli_numBits(long[] p_vli) {
		return vli_numBits(p_vli, 0) ;
	}

	/* Sets p_dest = p_src. */
	public static void vli_set(long[] p_dest, long[] p_src) {
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			p_dest[i] = p_src[i];
		}
	}

	public static void vli_set(long[] p_dest, int di, long[] p_src, int si) {
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			p_dest[i + di] = p_src[i + si];
		}
	}

	/* Returns sign of p_left - p_right. */

	static int vli_cmp(long[] p_left, int i1, long[] p_right, int i2) {
		int i;
		for (i = NUM_ECC_DIGITS - 1; i >= 0; --i) {
			int c = compareUnsigned(p_left[i + i1], p_right[i + i2]);
			if (c != 0)
				return c;
		}
		return 0;
	}
	static int vli_cmp(long[] p_left, long[] p_right) {
		return vli_cmp(p_left, 0, p_right, 0) ;
	}

	/*
	 * Computes p_result = p_in << c, returning carry. Can modify in place (if
	 * p_result == p_in). 0 < p_shift < 64.
	 */
	public static long vli_lshift(long[] p_result, int i1, long[] p_in, int i2, int p_shift) {
		long l_carry = 0;
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			long l_temp = p_in[i2+i];
			p_result[i1+i] = (l_temp << p_shift) | l_carry;
			l_carry = l_temp >>> (64 - p_shift);
		}
		return l_carry;
	}
	
	public static long vli_lshift(long[] p_result, long[] p_in, int p_shift) {
		return vli_lshift(p_result, 0, p_in, 0, p_shift) ;
	}

	/* Computes p_vli = p_vli >> 1. */
	public static void vli_rshift1(long[] p_vli) {
		long l_carry = 0;
		long[] b = new long[4];
		vli_set(b, p_vli);
		int index = NUM_ECC_DIGITS - 1;
		for (; index >= 0; index--) {
			b[index] = (p_vli[index] >>> 1) | l_carry;
			l_carry = p_vli[index] << 63;
		}
		vli_set(p_vli, b);
		// return b;
	}

	public static void vli_rshift1(long[] p_vli, int idx) {
		long l_carry = 0;
		long[] b = new long[4];
		vli_set(b, 0, p_vli, idx);
		int index = NUM_ECC_DIGITS - 1;
		for (; index >= 0; index--) {
			b[index] = (p_vli[index + idx] >>> 1) | l_carry;
			l_carry = p_vli[index + idx] << 63;
		}
		vli_set(p_vli, idx, b, 0);
		// return b;
	}

	/*
	 * Computes p_result = p_left + p_right, returning carry. Can modify in place.
	 */
	public static long vli_add(long[] p_result, long[] p_left, long[] p_right) {
		long l_carry = 0;
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			long l_sum = p_left[i] + p_right[i] + l_carry;
			if (l_sum != p_left[i]) {
				l_carry = (compareUnsigned(l_sum, p_left[i]) < 0 ? 1 : 0);
			}
			p_result[i] = l_sum;
		}
		return l_carry;
	}

	/*
	 * Computes p_result = p_left - p_right, returning borrow. Can modify in place.
	 */
	public static long vli_sub(long[] p_result, int i1, long[] p_left, int i2, long[] p_right, int i3) {
		long l_borrow = 0;
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			long l_diff = p_left[i + i2] - p_right[i + i3] - l_borrow;
			if (l_diff != p_left[i + i2]) {
				l_borrow = (compareUnsigned(l_diff, p_left[i + i2]) > 0 ? 1 : 0);
			}
			p_result[i + i1] = l_diff;
		}
		return l_borrow;
	}
	
	public static long vli_sub(long[] p_result, long[] p_left, long[] p_right) {
		return vli_sub(p_result, 0, p_left, 0, p_right, 0);
	}


	public static Long128 mul_64_64(long p_left, long p_right) {
		Long128 l_result = new Long128();

		long a0 = p_left & 0xffffffffl;
		long a1 = p_left >>> 32;
		long b0 = p_right & 0xffffffffl;
		long b1 = p_right >>> 32;

		long m0 = a0 * b0;
		long m1 = a0 * b1;
		long m2 = a1 * b0;
		long m3 = a1 * b1;

		m2 += (m0 >>> 32);
		m2 += m1;
		if ( compareUnsigned(m2,m1)<0 ) { // overflow
			m3 += 0x100000000l;
		}

		l_result.m_low = (m0 & 0xffffffffl) | (m2 << 32);
		l_result.m_high = m3 + (m2 >>> 32);

		return l_result;
	}

	static Long128 add_128_128(Long128 a, Long128 b) {
		Long128 l_result = new Long128();
		l_result.m_low = a.m_low + b.m_low;
		l_result.m_high = a.m_high + b.m_high + (compareUnsigned(l_result.m_low, a.m_low) < 0 ? 1 : 0);
		return l_result;
	}

	static void vli_mult(long[] p_result, long[] p_left, long[] p_right) {
		Long128 r01 = new Long128(0, 0);
		long r2 = 0;

		int i, k;

		/* Compute each digit of p_result in sequence, maintaining the carries. */
		for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; ++k) {
			int l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
			for (i = l_min; i <= k && i < NUM_ECC_DIGITS; ++i) {
				Long128 l_product = mul_64_64(p_left[i], p_right[k - i]);
				r01 = add_128_128(r01, l_product);
				r2 += (compareUnsigned(r01.m_high, l_product.m_high) < 0 ? 1 : 0);
			}
			p_result[k] = r01.m_low;
			r01.m_low = r01.m_high;
			r01.m_high = r2;
			r2 = 0;
		}

		p_result[NUM_ECC_DIGITS * 2 - 1] = r01.m_low;
	}

	static void vli_square(long[] p_result, long[] p_left) {
		Long128 r01 = new Long128(0, 0);
		long r2 = 0;

		int i, k;
		for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; ++k) {
			int l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
			for (i = l_min; i <= k && i <= k - i; ++i) {
//				System.out.println("vli_square");
//				print(p_left[i]) ;
//				print(p_left[k-i]) ;
				Long128 l_product = mul_64_64(p_left[i], p_left[k - i]);
//				print(l_product.m_high) ;
//				print(l_product.m_low) ;
				
				if (i < k - i) {
					r2 += l_product.m_high >>> 63;
					l_product.m_high = (l_product.m_high << 1) | (l_product.m_low >>> 63);
					l_product.m_low <<= 1;
				}
				r01 = add_128_128(r01, l_product);
				r2 += (compareUnsigned(r01.m_high, l_product.m_high) < 0 ? 1 : 0);
			}
			p_result[k] = r01.m_low;
			r01.m_low = r01.m_high;
			r01.m_high = r2;
			r2 = 0;
		}
		p_result[NUM_ECC_DIGITS * 2 - 1] = r01.m_low;
	}

	/*
	 * Computes p_result = (p_left + p_right) % p_mod. Assumes that p_left < p_mod
	 * and p_right < p_mod, p_result != p_mod.
	 */
	public static void vli_modAdd(long[] p_result, long[] p_left, long[] p_right, long[] p_mod) {
		long l_carry = vli_add(p_result, p_left, p_right);
		if (l_carry != 0 || vli_cmp(p_result, p_mod) >= 0) { /*
																 * p_result > p_mod (p_result = p_mod + remainder), so
																 * subtract p_mod to get remainder.
																 */
			vli_sub(p_result, p_result, p_mod);
		}
	}

	/*
	 * Computes p_result = (p_left - p_right) % p_mod. Assumes that p_left < p_mod
	 * and p_right < p_mod, p_result != p_mod.
	 */
	public static void vli_modSub(long[] p_result, long[] p_left, long[] p_right, long[] p_mod) {
		long l_borrow = vli_sub(p_result, p_left, p_right);
		if (l_borrow != 0) { /*
								 * In this case, p_result == -diff == (max int) - diff. Since -x % d == d - x,
								 * we can get the correct result from p_result + p_mod (with overflow).
								 */
			vli_add(p_result, p_result, p_mod);
		}
	}

	/*
	 * Computes p_result = p_product % curve_p from
	 * http://www.nsa.gov/ia/_files/nist-routines.pdf
	 */
	public static void vli_mmod_fast(long[] p_result, long[] p_product) {
		long[] l_tmp = new long[NUM_ECC_DIGITS];
		long l_carry;

		/* t */
		vli_set(p_result, p_product);

		/* s1 */
		l_tmp[0] = 0;
		l_tmp[1] = p_product[5] & 0xffffffff00000000l;
		l_tmp[2] = p_product[6];
		l_tmp[3] = p_product[7];
		l_carry = vli_lshift(l_tmp, l_tmp, 1);
		l_carry += vli_add(p_result, p_result, l_tmp);
//		print("p_result=", p_result) ;
//		print(l_carry) ;

		/* s2 */
		l_tmp[1] = p_product[6] << 32;
		l_tmp[2] = (p_product[6] >>> 32) | (p_product[7] << 32);
		l_tmp[3] = p_product[7] >>> 32;
		l_carry += vli_lshift(l_tmp, l_tmp, 1);
		l_carry += vli_add(p_result, p_result, l_tmp);
//		print("p_result=", p_result) ;
//		print(l_carry) ;
//		print("l_tmp=", l_tmp) ;

		/* s3 */
		l_tmp[0] = p_product[4];
//		print(p_product[5]) ;
		l_tmp[1] = p_product[5] & 0xffffffffl; // fail. l bug fix!!!!!!!!! 0xffffffff != 0xffffffffl !!!!!!!!!!!!!
//		print(l_tmp[1]) ;
		l_tmp[2] = 0;
		l_tmp[3] = p_product[7];
//		print("l_tmp2=", l_tmp) ;
		l_carry += vli_add(p_result, p_result, l_tmp);
//		print("s3 p_result=", p_result) ;
//		print(l_carry) ;

		/* s4 */
		l_tmp[0] = (p_product[4] >>> 32) | (p_product[5] << 32);
		l_tmp[1] = (p_product[5] >>> 32) | (p_product[6] & 0xffffffff00000000l);
		l_tmp[2] = p_product[7];
		l_tmp[3] = (p_product[6] >>> 32) | (p_product[4] << 32);
		l_carry += vli_add(p_result, p_result, l_tmp);
//		print("p_result=", p_result) ;
//		print(l_carry) ;

		/* d1 */
		l_tmp[0] = (p_product[5] >>> 32) | (p_product[6] << 32);
		l_tmp[1] = (p_product[6] >>> 32);
		l_tmp[2] = 0;
		l_tmp[3] = (p_product[4] & 0xffffffffl) | (p_product[5] << 32);
		l_carry -= vli_sub(p_result, p_result, l_tmp);
//		print("p_result=", p_result) ;
//		print(l_carry) ;

		/* d2 */
		l_tmp[0] = p_product[6];
		l_tmp[1] = p_product[7];
		l_tmp[2] = 0;
		l_tmp[3] = (p_product[4] >>> 32) | (p_product[5] & 0xffffffff00000000l);
		l_carry -= vli_sub(p_result, p_result, l_tmp);
//		print("p_result=", p_result) ;
//		print(l_carry) ;

		/* d3 */
		l_tmp[0] = (p_product[6] >>> 32) | (p_product[7] << 32);
		l_tmp[1] = (p_product[7] >>> 32) | (p_product[4] << 32);
		l_tmp[2] = (p_product[4] >>> 32) | (p_product[5] << 32);
		l_tmp[3] = (p_product[6] << 32);
		l_carry -= vli_sub(p_result, p_result, l_tmp);
//		print("p_result=", p_result) ;
//		print(l_carry) ;

		/* d4 */
		l_tmp[0] = p_product[7];
		l_tmp[1] = p_product[4] & 0xffffffff00000000l;
		l_tmp[2] = p_product[5];
		l_tmp[3] = p_product[6] & 0xffffffff00000000l;
		l_carry -= vli_sub(p_result, p_result, l_tmp);
//		print("p_result=", p_result) ;
//		print(l_carry) ;

		if (l_carry < 0) {
			do {
				l_carry += vli_add(p_result, p_result, curve_p);
			} while (l_carry < 0);
		} else {
			while (l_carry != 0 || vli_cmp(curve_p, p_result) != 1) {
				l_carry -= vli_sub(p_result, p_result, curve_p);
			}
		}
	}

	/* Computes p_result = (p_left * p_right) % curve_p. */
	public static void vli_modMult_fast(long[] p_result, long[] p_left, long[] p_right) {
		long[] l_product = new long[2 * NUM_ECC_DIGITS];
		vli_mult(l_product, p_left, p_right);
		vli_mmod_fast(p_result, l_product);
	}

	/* Computes p_result = p_left^2 % curve_p. */
	public static void vli_modSquare_fast(long[] p_result, long[] p_left) {
		long[] l_product = new long[2 * NUM_ECC_DIGITS];
		vli_square(l_product, p_left);
//		print("l_product=", l_product) ;
//		print("p_left=", p_left) ;
		vli_mmod_fast(p_result, l_product);
//		print("p_result=", p_result) ;
//		print("l_product=", l_product) ;
		
	}

	public static boolean EVEN(long[] vli) {
		return (vli[0] & 1) == 0;
	}

	// #define EVEN(vli) (!(vli[0] & 1))
	/*
	 * Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size. See
	 * "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
	 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
	 */
	public static void vli_modInv(long[] p_result, long[] p_input, long[] p_mod) {
		long[] a = new long[NUM_ECC_DIGITS];
		long[] b = new long[NUM_ECC_DIGITS];
		long[] u = new long[NUM_ECC_DIGITS];
		long[] v = new long[NUM_ECC_DIGITS];
		// uint64_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS], u[NUM_ECC_DIGITS],
		// v[NUM_ECC_DIGITS];
		long l_carry;
		int l_cmpResult;

		if (vli_isZero(p_input)) {
			vli_clear(p_result);
			return;
		}

		vli_set(a, p_input);
		vli_set(b, p_mod);
		vli_clear(u);
		u[0] = 1;
		vli_clear(v);

		while ((l_cmpResult = vli_cmp(a, b)) != 0) {
			l_carry = 0;
			if (EVEN(a)) {
				vli_rshift1(a);
				if (!EVEN(u)) {
					l_carry = vli_add(u, u, p_mod);
				}
				vli_rshift1(u);
				if (l_carry != 0) {
					u[NUM_ECC_DIGITS - 1] |= 0x8000000000000000l;
				}
			} else if (EVEN(b)) {
				vli_rshift1(b);
				if (!EVEN(v)) {
					l_carry = vli_add(v, v, p_mod);
				}
				vli_rshift1(v);
				if (l_carry != 0) {
					v[NUM_ECC_DIGITS - 1] |= 0x8000000000000000l;
				}
			} else if (l_cmpResult > 0) {
				vli_sub(a, a, b);
				vli_rshift1(a);
				if (vli_cmp(u, v) < 0) {
					vli_add(u, u, p_mod);
				}
				vli_sub(u, u, v);
				if (!EVEN(u)) {
					l_carry = vli_add(u, u, p_mod);
				}
				vli_rshift1(u);
				if (l_carry != 0) {
					u[NUM_ECC_DIGITS - 1] |= 0x8000000000000000l;
				}
			} else {
				vli_sub(b, b, a);
				vli_rshift1(b);
				if (vli_cmp(v, u) < 0) {
					vli_add(v, v, p_mod);
				}
				vli_sub(v, v, u);
				if (!EVEN(v)) {
					l_carry = vli_add(v, v, p_mod);
				}
				vli_rshift1(v);
				if (l_carry != 0) {
					v[NUM_ECC_DIGITS - 1] |= 0x8000000000000000l;
				}
			}
		}

		vli_set(p_result, u);
	}

	/* Returns 1 if p_point is the point at infinity, 0 otherwise. */
	public static boolean EccPoint_isZero(EccPoint p_point) {
		return (vli_isZero(p_point.x) && vli_isZero(p_point.y));
	}

	/*
	 * Point multiplication algorithm using Montgomery's ladder with co-Z
	 * coordinates. From http://eprint.iacr.org/2011/338.pdf
	 */

	/* Double in place */
	static void EccPoint_double_jacobian(long[] X1, long[] Y1, long[] Z1) {
		/* t1 = X, t2 = Y, t3 = Z */
		long[] t4 = new long[NUM_ECC_DIGITS];
		long[] t5 = new long[NUM_ECC_DIGITS];

		if (vli_isZero(Z1)) {
			return;
		}

		vli_modSquare_fast(t4, Y1); /* t4 = y1^2 */
		
//		System.out.println("t4=") ;
//		print(t4) ;
		
		vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
		vli_modSquare_fast(t4, t4); /* t4 = y1^4 */
		vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
		vli_modSquare_fast(Z1, Z1); /* t3 = z1^2 */

		vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
		vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
		vli_modSub(Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
		vli_modMult_fast(X1, X1, Z1); /* t1 = x1^2 - z1^4 */

		vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
		vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
		if (vli_testBit(X1, 0) != 0) {
			long l_carry = vli_add(X1, X1, curve_p);
			vli_rshift1(X1);
			X1[NUM_ECC_DIGITS - 1] |= l_carry << 63;
		} else {
			vli_rshift1(X1);
		}
		/* t1 = 3/2*(x1^2 - z1^4) = B */

		vli_modSquare_fast(Z1, X1); /* t3 = B^2 */
		vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
		vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
		vli_modSub(t5, t5, Z1, curve_p); /* t5 = A - x3 */
		vli_modMult_fast(X1, X1, t5); /* t1 = B * (A - x3) */
		vli_modSub(t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */

		vli_set(X1, Z1);
		vli_set(Z1, Y1);
		vli_set(Y1, t4);
	}

	/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
	public static void apply_z(long[] X1, long[] Y1, long[] Z) {
		long[] t1 = new long[NUM_ECC_DIGITS];

		vli_modSquare_fast(t1, Z); /* z^2 */
		vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
		vli_modMult_fast(t1, t1, Z); /* z^3 */
		vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
	}

	/* P = (x1, y1) => 2P, (x2, y2) => P' */
	public static void XYcZ_initial_double(long[] X1, long[] Y1, long[] X2, long[] Y2, long[] p_initialZ) {
		long[] z = new long[NUM_ECC_DIGITS];

		vli_set(X2, X1);
		vli_set(Y2, Y1);

		vli_clear(z);
		z[0] = 1;

		if (p_initialZ != null && !vli_isZero(p_initialZ)) {
			System.out.println("set init.");
			vli_set(z, p_initialZ);
		}
		
//		System.out.println("initdouble");
//		print(X1);
//		print(Y1);
//		print(z) ;

		apply_z(X1, Y1, z);


		EccPoint_double_jacobian(X1, Y1, z);
//		System.out.println("jaco");
//		print(X1);
//		print(Y1);
//		print(z) ;

		apply_z(X2, Y2, z);
	}

	/*
	 * Input P = (x1, y1, Z), Q = (x2, y2, Z) Output P' = (x1', y1', Z3), P + Q =
	 * (x3, y3, Z3) or P => P', Q => P + Q
	 */
	public static void XYcZ_add(long[] X1, long[] Y1, long[] X2, long[] Y2) {
		/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
		long[] t5 = new long[NUM_ECC_DIGITS];

		vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
		vli_modSquare_fast(t5, t5); /* t5 = (x2 - x1)^2 = A */
		vli_modMult_fast(X1, X1, t5); /* t1 = x1*A = B */
		vli_modMult_fast(X2, X2, t5); /* t3 = x2*A = C */
		vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */
		vli_modSquare_fast(t5, Y2); /* t5 = (y2 - y1)^2 = D */

		vli_modSub(t5, t5, X1, curve_p); /* t5 = D - B */
		vli_modSub(t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */
		vli_modSub(X2, X2, X1, curve_p); /* t3 = C - B */
		vli_modMult_fast(Y1, Y1, X2); /* t2 = y1*(C - B) */
		vli_modSub(X2, X1, t5, curve_p); /* t3 = B - x3 */
		vli_modMult_fast(Y2, Y2, X2); /* t4 = (y2 - y1)*(B - x3) */
		vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

		vli_set(X2, t5);
	}

	/*
	 * Input P = (x1, y1, Z), Q = (x2, y2, Z) Output P + Q = (x3, y3, Z3), P - Q =
	 * (x3', y3', Z3) or P => P - Q, Q => P + Q
	 */
	public static void XYcZ_addC(long[] X1, long[] Y1, long[] X2, long[] Y2) {
		/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
		long[] t5 = new long[NUM_ECC_DIGITS];
		long[] t6 = new long[NUM_ECC_DIGITS];
		long[] t7 = new long[NUM_ECC_DIGITS];

		vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
		vli_modSquare_fast(t5, t5); /* t5 = (x2 - x1)^2 = A */
		vli_modMult_fast(X1, X1, t5); /* t1 = x1*A = B */
		vli_modMult_fast(X2, X2, t5); /* t3 = x2*A = C */
		vli_modAdd(t5, Y2, Y1, curve_p); /* t4 = y2 + y1 */
		vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */

		vli_modSub(t6, X2, X1, curve_p); /* t6 = C - B */
		vli_modMult_fast(Y1, Y1, t6); /* t2 = y1 * (C - B) */
		vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
		vli_modSquare_fast(X2, Y2); /* t3 = (y2 - y1)^2 */
		vli_modSub(X2, X2, t6, curve_p); /* t3 = x3 */

		vli_modSub(t7, X1, X2, curve_p); /* t7 = B - x3 */
		vli_modMult_fast(Y2, Y2, t7); /* t4 = (y2 - y1)*(B - x3) */
		vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

		vli_modSquare_fast(t7, t5); /* t7 = (y2 + y1)^2 = F */
		vli_modSub(t7, t7, t6, curve_p); /* t7 = x3' */
		vli_modSub(t6, t7, X1, curve_p); /* t6 = x3' - B */
		vli_modMult_fast(t6, t6, t5); /* t6 = (y2 + y1)*(x3' - B) */
		vli_modSub(Y1, t6, Y1, curve_p); /* t2 = y3' */

		vli_set(X1, t7);
	}

	public static void EccPoint_mult(EccPoint p_result, EccPoint p_point, long[] p_scalar, long[] p_initialZ) {
		/* R0 and R1 */
		long[][] Rx = new long[2][NUM_ECC_DIGITS];
		long[][] Ry = new long[2][NUM_ECC_DIGITS];
		long[] z = new long[NUM_ECC_DIGITS];

		int i, nb;

		vli_set(Rx[1], p_point.x);
		vli_set(Ry[1], p_point.y);

//		System.out.println("Rx1=");
//		print(Rx[1]) ;
//		System.out.println("Ry1=");
//		print(Ry[1]) ;

		XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);
		
//		System.out.println("Rx0=");
//		print(Rx[0]) ;

		for (i = vli_numBits(p_scalar) - 2; i > 0; --i) {
			nb = vli_testBit(p_scalar, i) == 0 ? 1 : 0; // !vli........
			XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
			XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
		}

		nb = vli_testBit(p_scalar, 0) == 0 ? 1 : 0; // !vli....
		XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

		/* Find final 1/Z value. */
		vli_modSub(z, Rx[1], Rx[0], curve_p); /* X1 - X0 */
		vli_modMult_fast(z, z, Ry[1 - nb]); /* Yb * (X1 - X0) */
		vli_modMult_fast(z, z, p_point.x); /* xP * Yb * (X1 - X0) */
		vli_modInv(z, z, curve_p); /* 1 / (xP * Yb * (X1 - X0)) */
		vli_modMult_fast(z, z, p_point.y); /* yP / (xP * Yb * (X1 - X0)) */
		vli_modMult_fast(z, z, Rx[1 - nb]); /* Xb * yP / (xP * Yb * (X1 - X0)) */
		/* End 1/Z calculation */

		XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);

		apply_z(Rx[0], Ry[0], z);

		vli_set(p_result.x, Rx[0]);
		vli_set(p_result.y, Ry[0]);
	}

	public static void ecc_bytes2native(long[] p_native, int i1, byte[] p_bytes, int i2) {
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			int idx = 8 * (NUM_ECC_DIGITS - 1 - i) + i2;
			// fail
/*			p_native[i + i1] = ((long) p_bytes[idx + 0] << 56) | ((long) p_bytes[idx + 1] << 48)
					| ((long) p_bytes[idx + 2] << 40) | ((long) p_bytes[idx + 3] << 32)
					| ((long) p_bytes[idx + 4] << 24) | ((long) p_bytes[idx + 5] << 16) | ((long) p_bytes[idx + 6] << 8)
					| (long) p_bytes[idx + 7];
*/
			p_native[i + i1] = ((long) (0xff&p_bytes[idx + 0]) << 56) 
					| ((long) (0xff&p_bytes[idx + 1]) << 48)
					| ((long) (0xff&p_bytes[idx + 2]) << 40) 
					| ((long) (0xff&p_bytes[idx + 3]) << 32)
					| ((long) (0xff&p_bytes[idx + 4]) << 24) 
					| ((long) (0xff&p_bytes[idx + 5]) << 16) 
					| ((long) (0xff&p_bytes[idx + 6]) << 8)
					| (long) (0xff&p_bytes[idx + 7]);

//			print(p_native[i+i1]) ;
		}
	}

	public static void ecc_bytes2native(long[] p_native, byte[] p_bytes) {
		ecc_bytes2native(p_native, 0, p_bytes, 0);
	}

	public static void ecc_native2bytes(byte[] p_bytes, int i1, long[] p_native, int i2) {
		int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i) {
			// uint8_t *p_digit = p_bytes + 8 * (NUM_ECC_DIGITS - 1 - i);
			int idx = 8 * (NUM_ECC_DIGITS - 1 - i) + i1;
			p_bytes[idx + 0] = (byte) (p_native[i + i2] >>> 56);
			p_bytes[idx + 1] = (byte) (p_native[i + i2] >>> 48);
			p_bytes[idx + 2] = (byte) (p_native[i + i2] >>> 40);
			p_bytes[idx + 3] = (byte) (p_native[i + i2] >>> 32);
			p_bytes[idx + 4] = (byte) (p_native[i + i2] >>> 24);
			p_bytes[idx + 5] = (byte) (p_native[i + i2] >>> 16);
			p_bytes[idx + 6] = (byte) (p_native[i + i2] >>> 8);
			p_bytes[idx + 7] = (byte) (p_native[i + i2]);
		}
	}

	public static void ecc_native2bytes(byte[] p_bytes, long[] p_native) {
		ecc_native2bytes(p_bytes, 0, p_native, 0);
	}

	/* Compute a = sqrt(a) (mod curve_p). */
	public static void mod_sqrt(long[] a) {
		int i;
		long[] p1 = new long[NUM_ECC_DIGITS];
		long[] l_result = new long[NUM_ECC_DIGITS];
		p1[0] = 1;
		l_result[0] = 1;

		/*
		 * Since curve_p == 3 (mod 4) for all supported curves, we can compute sqrt(a) =
		 * a^((curve_p + 1) / 4) (mod curve_p).
		 */
		vli_add(p1, curve_p, p1); /* p1 = curve_p + 1 */
		for (i = vli_numBits(p1) - 1; i > 1; --i) {
			vli_modSquare_fast(l_result, l_result);
			if (vli_testBit(p1, i) != 0) {
				vli_modMult_fast(l_result, l_result, a);
			}
		}
		vli_set(a, l_result);
	}

	public static void ecc_point_decompress(EccPoint p_point, byte[] p_compressed) {
		long[] _3 = new long[NUM_ECC_DIGITS];// = {3}; /* -a = 3 */
		_3[0] = 3;
		
//		System.out.println("p_compressed=");
//		print(p_compressed) ;
		
		ecc_bytes2native(p_point.x, 0, p_compressed, 1);
		
//		print(p_point.x); 

		vli_modSquare_fast(p_point.y, p_point.x); /* y = x^2 */
		vli_modSub(p_point.y, p_point.y, _3, curve_p); /* y = x^2 - 3 */
		vli_modMult_fast(p_point.y, p_point.y, p_point.x); /* y = x^3 - 3x */
		vli_modAdd(p_point.y, p_point.y, curve_b, curve_p); /* y = x^3 - 3x + b */

		mod_sqrt(p_point.y);

		if ((p_point.y[0] & 0x01) != (p_compressed[0] & 0x01)) {
			vli_sub(p_point.y, curve_p, p_point.y);
		}
	}

	// [ECC_BYTES+1], [ECC_BYTES]
	public static boolean ecc_make_key(byte[] p_publicKey, byte[] p_privateKey) {
		long[] l_private = new long[NUM_ECC_DIGITS];
		EccPoint l_public = new EccPoint();
		int l_tries = 0;

		do {
			if (getRandomNumber(l_private) == 0 || (l_tries++ >= MAX_TRIES)) {
				return false;
			}
			if (vli_isZero(l_private)) {
				continue;
			}

			/*
			 * Make sure the private key is in the range [1, n-1]. For the supported curves,
			 * n is always large enough that we only need to subtract once at most.
			 */
			if (vli_cmp(curve_n, l_private) != 1) {
				vli_sub(l_private, l_private, curve_n);
			}

			EccPoint_mult(l_public, curve_G, l_private, null);
//			System.out.println("l_public");
//			print(l_public.x) ;
//			print(l_public.y) ; 
		} while (EccPoint_isZero(l_public));

		ecc_native2bytes(p_privateKey, l_private);
		ecc_native2bytes(p_publicKey, 1, l_public.x, 0);
		p_publicKey[0] = (byte) (2 + (l_public.y[0] & 0x01));
		return true;
	}

	// [ECC_BYTES+1], [ECC_BYTES], [ECC_BYTES]
	public static boolean ecdh_shared_secret(byte[] p_publicKey, byte[] p_privateKey, byte[] p_secret) {
		EccPoint l_public = new EccPoint();
		long[] l_private = new long[NUM_ECC_DIGITS];
		long[] l_random = new long[NUM_ECC_DIGITS];

		if (getRandomNumber(l_random) == 0) {
			return false;
		}

		ecc_point_decompress(l_public, p_publicKey);
		
//		System.out.println("l_public=");
//		print(l_public.x);
//		print(l_public.y);
		
		ecc_bytes2native(l_private, p_privateKey);

		EccPoint l_product = new EccPoint();
		EccPoint_mult(l_product, l_public, l_private, l_random);

		ecc_native2bytes(p_secret, l_product.x);

		return !EccPoint_isZero(l_product);
	}

	/* -------- ECDSA code -------- */

	/* Computes p_result = (p_left * p_right) % p_mod. */
	public static void vli_modMult(long[] p_result, long[] p_left, long[] p_right, long[] p_mod) {
		long[] l_product = new long[2 * NUM_ECC_DIGITS];
		long[] l_modMultiple = new long[2 * NUM_ECC_DIGITS];
		int l_digitShift, l_bitShift;
		int l_productBits;
		int l_modBits = vli_numBits(p_mod);

		vli_mult(l_product, p_left, p_right);
		
		l_productBits = vli_numBits(l_product, NUM_ECC_DIGITS);
		
		if (l_productBits != 0) {
			l_productBits += NUM_ECC_DIGITS * 64;
		} else {
			l_productBits = vli_numBits(l_product);
		}

		if (l_productBits < l_modBits) { /* l_product < p_mod. */
			vli_set(p_result, l_product);
			return;
		}

		/*
		 * Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
		 * power of two possible while still resulting in a number less than p_left.
		 */
		vli_clear(l_modMultiple);
		vli_clear(l_modMultiple, NUM_ECC_DIGITS);

		l_digitShift = (l_productBits - l_modBits) / 64;
		l_bitShift = (l_productBits - l_modBits) % 64;
		if (l_bitShift != 0) {
			l_modMultiple[l_digitShift + NUM_ECC_DIGITS] = vli_lshift(l_modMultiple , l_digitShift, p_mod, 0, l_bitShift);
		} else {
        	vli_set(l_modMultiple , l_digitShift, p_mod, 0) ;
		}

		/* Subtract all multiples of p_mod to get the remainder. */
		vli_clear(p_result);
		p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
		while (l_productBits > NUM_ECC_DIGITS * 64 || vli_cmp(l_modMultiple, p_mod) >= 0) {
			int l_cmp = vli_cmp(l_modMultiple, NUM_ECC_DIGITS, l_product, NUM_ECC_DIGITS);
			if (l_cmp < 0 || (l_cmp == 0 && vli_cmp(l_modMultiple, l_product) <= 0)) {
				if (vli_sub(l_product, l_product, l_modMultiple) != 0) { /* borrow */
					vli_sub(l_product, NUM_ECC_DIGITS, l_product, NUM_ECC_DIGITS, p_result, 0);
				}
				vli_sub(l_product, NUM_ECC_DIGITS, l_product, NUM_ECC_DIGITS, l_modMultiple, NUM_ECC_DIGITS);
			}
			long l_carry = (l_modMultiple[NUM_ECC_DIGITS] & 0x01) << 63;
			vli_rshift1(l_modMultiple, NUM_ECC_DIGITS);
			vli_rshift1(l_modMultiple);
			l_modMultiple[NUM_ECC_DIGITS - 1] |= l_carry;

			--l_productBits;
		}
		vli_set(p_result, l_product);
	}

	public static int umax(int a, int b) {
		if (compareUnsigned(a, b) > 0)
			return a;
		return b;
	}

	// const uint8_t p_privateKey[ECC_BYTES], const uint8_t p_hash[ECC_BYTES],
	// uint8_t p_signature[ECC_BYTES*2]
	public static int ecdsa_sign(byte[] p_privateKey, byte[] p_hash, byte[] p_signature) {
		long[] k = new long[NUM_ECC_DIGITS];
		long[] l_tmp = new long[NUM_ECC_DIGITS];
		long[] l_s = new long[NUM_ECC_DIGITS];
		EccPoint p = new EccPoint();
		int l_tries = 0;

		do {
			if (getRandomNumber(k) == 0 || (l_tries++ >= MAX_TRIES)) {
				return 0;
			}
			if (vli_isZero(k)) {
				continue;
			}

			if (vli_cmp(curve_n, k) != 1) {
				vli_sub(k, k, curve_n);
			}

			/* tmp = k * G */
			EccPoint_mult(p, curve_G, k, null);

			/* r = x1 (mod n) */
			if (vli_cmp(curve_n, p.x) != 1) {
				vli_sub(p.x, p.x, curve_n);
			}
		} while (vli_isZero(p.x));

		ecc_native2bytes(p_signature, p.x);

		ecc_bytes2native(l_tmp, p_privateKey);
		vli_modMult(l_s, p.x, l_tmp, curve_n); /* s = r*d */
		ecc_bytes2native(l_tmp, p_hash);
		vli_modAdd(l_s, l_tmp, l_s, curve_n); /* s = e + r*d */
		vli_modInv(k, k, curve_n); /* k = 1 / k */
		vli_modMult(l_s, l_s, k, curve_n); /* s = (e + r*d) / k */
		ecc_native2bytes(p_signature, ECC_BYTES, l_s, 0);

		return 1;
	}

	// const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_hash[ECC_BYTES],
	// const uint8_t p_signature[ECC_BYTES*2]
	public static boolean ecdsa_verify(byte[] p_publicKey, byte[] p_hash, byte[] p_signature) {
		long[] u1 = new long[NUM_ECC_DIGITS];
		long[] u2 = new long[NUM_ECC_DIGITS];
		long[] z = new long[NUM_ECC_DIGITS];
		EccPoint l_public = new EccPoint();
		EccPoint l_sum = new EccPoint();
		long[] rx = new long[NUM_ECC_DIGITS], ry = new long[NUM_ECC_DIGITS];
		long[] tx = new long[NUM_ECC_DIGITS], ty = new long[NUM_ECC_DIGITS], tz = new long[NUM_ECC_DIGITS];

		long[] l_r = new long[NUM_ECC_DIGITS], l_s = new long[NUM_ECC_DIGITS];

		ecc_point_decompress(l_public, p_publicKey);
		ecc_bytes2native(l_r, p_signature);
		ecc_bytes2native(l_s, 0, p_signature, ECC_BYTES);

		if (vli_isZero(l_r) || vli_isZero(l_s)) { /* r, s must not be 0. */
			return false;
		}

		if (vli_cmp(curve_n, l_r) != 1 || vli_cmp(curve_n, l_s) != 1) { /* r, s must be < n. */
			return false;
		}

		/* Calculate u1 and u2. */
		vli_modInv(z, l_s, curve_n); /* Z = s^-1 */
		ecc_bytes2native(u1, p_hash);
		vli_modMult(u1, u1, z, curve_n); /* u1 = e/s */
		vli_modMult(u2, l_r, z, curve_n); /* u2 = r/s */

		/* Calculate l_sum = G + Q. */
		vli_set(l_sum.x, l_public.x);
		vli_set(l_sum.y, l_public.y);
		vli_set(tx, curve_G.x);
		vli_set(ty, curve_G.y);
		vli_modSub(z, l_sum.x, tx, curve_p); /* Z = x2 - x1 */
		XYcZ_add(tx, ty, l_sum.x, l_sum.y);
		vli_modInv(z, z, curve_p); /* Z = 1/Z */
		apply_z(l_sum.x, l_sum.y, z);

		/* Use Shamir's trick to calculate u1*G + u2*Q */
		EccPoint[] l_points = new EccPoint[4];
		l_points[0] = null;
		l_points[1] = new EccPoint(curve_G);
		l_points[2] = new EccPoint(l_public);
		l_points[3] = new EccPoint(l_sum);
		// EccPoint *l_points[4] = {NULL, &curve_G, &l_public, &l_sum};

		int l_numBits = umax(vli_numBits(u1), vli_numBits(u2));

		// EccPoint *l_point = l_points[(!!vli_testBit(u1, l_numBits-1)) |
		// ((!!vli_testBit(u2, l_numBits-1)) << 1)];
		// (!!vli_testBit(u1, l_numBits-1)) | ((!!vli_testBit(u2, l_numBits-1)) << 1)
		int index = (vli_testBit(u1, l_numBits - 1) == 0 ? 0 : 1)
				| ((vli_testBit(u2, l_numBits - 1) == 0 ? 0 : 1) << 1);
		EccPoint l_point = l_points[index];

		vli_set(rx, l_point.x);
		vli_set(ry, l_point.y);
		vli_clear(z);
		z[0] = 1;

		int i;
		for (i = l_numBits - 2; i >= 0; --i) {
			EccPoint_double_jacobian(rx, ry, z);
			// int l_index = (!!vli_testBit(u1, i)) | ((!!vli_testBit(u2, i)) << 1);
			int l_index = (vli_testBit(u1, i) == 0 ? 0 : 1) | ((vli_testBit(u2, i) == 0 ? 0 : 1) << 1);
			l_point = l_points[l_index];
			if (l_point != null) {
				vli_set(tx, l_point.x);
				vli_set(ty, l_point.y);
				apply_z(tx, ty, z);
				vli_modSub(tz, rx, tx, curve_p); /* Z = x2 - x1 */
				XYcZ_add(tx, ty, rx, ry);
				vli_modMult_fast(z, z, tz);
			}
		}

		vli_modInv(z, z, curve_p); /* Z = 1/Z */
		apply_z(rx, ry, z);

		/* v = x1 (mod n) */
		if (vli_cmp(curve_n, rx) != 1) {
			vli_sub(rx, rx, curve_n);
		}

		/* Accept only if v == r. */
		return (vli_cmp(rx, l_r) == 0);
	}

	////////////////////////////////////////////////////////////////////////////////////
	public static void printdash() {
		for (int i = 0; i < 80; i++)
			System.out.print("-");
		System.out.println("");
	}

	public static void print(String s) {
		System.out.println(s);
	}

	public static void print(String h, byte[] b) {
		System.out.print(h+" ");
		for (int i = 0; i < b.length; i++) {
			String hex = String.format("%02x", b[i] & 0xFF);
			System.out.print(hex + " ");
		}
		System.out.println("");
	}
	
	public static void print(byte[] b) {
		print("", b) ;
	}

	public static String longToHexZeroPad(long l) {
		String hex = Long.toHexString(l);
		int hexlen = hex.length();
		if (hexlen != 2 * 8) {
			for (int i = 0; i < 2 * 8 - hexlen; i++)
				hex = "0" + hex;
		}
		return hex;
	}

	public static void print(long[] bi) {
		for (int i = 0; i < bi.length; i++) {
			System.out.print(longToHexZeroPad(bi[i]) + " ");
		}
		System.out.println("");
	}

	public static void print(String h, long[] bi) {
		System.out.println(h);
		for (int i = 0; i < bi.length; i++) {
			System.out.print(longToHexZeroPad(bi[i]) + " ");
		}
		System.out.println("");
	}

	public static void print(long l) {
		System.out.println(longToHexZeroPad(l));
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String sval = "";
		String hex = "";
		String msg = "";
		long l = 0;
		int i = 0;

		String s = "1a00Ff45";
		String s2 = "";
		byte[] r = null;

		/*
		printdash();
		print("hexa string -> byte array " + s);
		r = hexStringToByteArray(s);
		print(r);
		l = Long.parseLong(s, 16);
		s = Long.toBinaryString(l);
		s2 = Long.toHexString(l);
		print(String.format("input value=%d  bin=%s  => java Big Endian! hex=%s", l, s, s2));

		printdash();
		s = "c0ffffffffffffff"; // overflow (sign bit set)
		print("hexa string -> byte array " + s);
		r = hexStringToByteArray(s);
		print(r);
		l = Long.parseUnsignedLong(s, 16);
		s = Long.toBinaryString(l);
		s2 = Long.toHexString(l);
		print(String.format("input value=%d  bin=%s  => java Big Endian! hex=%s", l, s, s2));

		// ECC.vli_clear(ECC.curve_test);
		// if ( ECC.vli_isZero(ECC.curve_test)==1 )
		// print("zero");
		// else
		// print("not zero") ;

		print(ECC.curve_test);
		print(ECC.curve_test2);
		print(ECC.vli_cmp(ECC.curve_test, ECC.curve_test2));

		print(ECC.curve_test);
		print(ECC.curve_test2);
		print(ECC.vli_cmp(ECC.curve_test, ECC.curve_test2));

		// Long[] p_result = new Long[4] ;
		long[] l_result = new long[4];
		// long lcarry = ECC.vli_add(p_result, ECC.curve_test, ECC.curve_test2);
		long lcarry = ECC.vli_sub(l_result, ECC.curve_test, ECC.curve_test2);
		// long[] l_ret = ArrayUtils.toPrimitive(p_result);
		print(l_result);
		print(lcarry);

		print(ECC.curve_test);
		ECC.vli_rshift1(ECC.curve_test);
		print(ECC.curve_test);
		ECC.vli_rshift1(ECC.curve_test);
		print(ECC.curve_test);
		ECC.vli_rshift1(ECC.curve_test);
		print(ECC.curve_test);
		*/

		// [ECC_BYTES+1], [ECC_BYTES]
		byte[] pub = new byte[ECC_BYTES + 1];
		byte[] pri = new byte[ECC_BYTES];
		byte[] pub2 = new byte[ECC_BYTES + 1];
		byte[] pri2 = new byte[ECC_BYTES];
		boolean bret;

		print("ecc_make_key");
		bret = ECC.ecc_make_key(pub, pri);
		System.out.println(bret);
		System.out.println("pub=");
		print(pub);
		System.out.println("pri=");
		print(pri);

		bret = ECC.ecc_make_key(pub2, pri2);
		System.out.println(bret);
		System.out.println("pub2=");
		print(pub2);
		System.out.println("pri2=");
		print(pri2);

		byte[] skey = new byte[ECC_BYTES];
		print("ecdh_shared_secret, pub, pri2");
		bret = ECC.ecdh_shared_secret(pub, pri2, skey);
		System.out.println(bret);
		print("skey1=", skey);
		
		byte[] skey2 = new byte[ECC_BYTES] ;
		print("ecdh_shared_secret, pub2, pri");
		bret = ECC.ecdh_shared_secret(pub2, pri, skey2);
		System.out.println(bret+" skeysize="+skey2.length);
		print("skey2=", skey2);
		if ( Arrays.equals(skey,  skey2) ) {
			System.out.println("shared key match ok.");
		} else {
			System.out.println("shared key failed!"); 
		}
		
		
		
		byte[] hash = new byte[ECC_BYTES] ; // 32 bytes. 256bit.
		byte[] signature = new byte[ECC_BYTES*2] ;
		String orgmsg = "hello world" ;
		try {
			hash = sha256(orgmsg.getBytes("UTF-8")) ;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/*
		// test debug hash
		for (i=0; i<hash.length; i++)
			hash[i] = (byte)i ;
		*/
		ECC.ecdsa_sign(pri, hash, signature) ;
		System.out.println("hash size="+hash.length);
		print(hash) ;
		System.out.println(byteArrayToHexString(hash));
		System.out.println("signature=");
		print(signature) ;
		
		bret = ECC.ecdsa_verify(pub, hash, signature);
		System.out.println("ecdsa_verify = "+bret);

	}

}
