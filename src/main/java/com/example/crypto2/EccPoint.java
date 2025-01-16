package com.example.crypto2;

public class EccPoint {
	private static final int ARRAY_SIZE = 4;
	
	public final long[] x;
	public final long[] y;
	
	public EccPoint() {
		x = new long[ARRAY_SIZE];
		y = new long[ARRAY_SIZE];
	}
	
	public EccPoint(long x0, long x1, long x2, long x3, long y0, long y1, long y2, long y3) {
		x = new long[ARRAY_SIZE];
		y = new long[ARRAY_SIZE];
		x[0] = x0;
		x[1] = x1;
		x[2] = x2;
		x[3] = x3;
		y[0] = y0;
		y[1] = y1;
		y[2] = y2;
		y[3] = y3;
	}
	
	public EccPoint(EccPoint d) {
		x = new long[ARRAY_SIZE];
		y = new long[ARRAY_SIZE];
		System.arraycopy(d.x, 0, x, 0, ARRAY_SIZE);
		System.arraycopy(d.y, 0, y, 0, ARRAY_SIZE);
	}
}

