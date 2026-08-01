package clj_nproxy.java;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Random;

public final class BytesUtils {
  private static final Random RANDOM = new SecureRandom();

  public static int length(byte[] b) {
    return b.length;
  }

  public static void copy(byte[] src, int srcFrom, byte[] dst, int dstFrom, int n) {
    System.arraycopy(src, srcFrom, dst, dstFrom, n);
  }

  public static byte[] copyOf(byte[] b) {
    return Arrays.copyOf(b, b.length);
  }

  public static byte[] copyOf(byte[] b, int n) {
    return Arrays.copyOf(b, n);
  }

  public static byte[] copyOfRange(byte[] b, int from, int to) {
    return Arrays.copyOfRange(b, from, to);
  }

  public static int compare(byte[] b1, byte[] b2) {
    return Arrays.compare(b1, b2);
  }

  public static int compare(byte[] b1, int b1From, int b1To, byte[] b2, int b2From, int b2To) {
    return Arrays.compare(b1, b1From, b1To, b2, b2From, b2To);
  }

  public static void fill(byte[] b, int i) {
    Arrays.fill(b, (byte) i);
  }

  public static void fill(byte[] b, int from, int to, int i) {
    Arrays.fill(b, from, to, (byte) i);
  }

  public static byte[] cat(Object... bs) {
    int len = 0;
    for (Object o : bs) {
      len += ((byte[]) o).length;
    }
    byte[] nb = new byte[len];
    int off = 0;
    for (Object o : bs) {
      byte[] b = (byte[]) o;
      System.arraycopy(b, 0, nb, off, b.length);
      off += b.length;
    }
    return nb;
  }

  public static byte[] reverse(byte[] b) {
    int len = b.length;
    byte[] nb = new byte[len];
    for (int i = 0; i < len; i++) {
      nb[i] = b[len - i - 1];
    }
    return nb;
  }

  public static byte[] leftAlign(byte[] b, int n) {
    return Arrays.copyOf(b, n);
  }

  public static byte[] rightAlign(byte[] b, int n) {
    int len = b.length;
    byte[] nb = new byte[n];
    System.arraycopy(b, Math.max(0, len - n), nb, Math.max(0, n - len), Math.min(len, n));
    return nb;
  }

  public static byte[] rand(int n) {
    byte[] b = new byte[n];
    RANDOM.nextBytes(b);
    return b;
  }

  public static byte[] strToBytes(String s) {
    return s.getBytes();
  }

  public static String bytesToStr(byte[] b) {
    return new String(b);
  }

  public static byte[] hexToBytes(String s) {
    return HexFormat.of().parseHex(s);
  }

  public static String bytesToHex(byte[] b) {
    return HexFormat.of().formatHex(b);
  }

  public static byte[] base64ToBytes(String s) {
    return Base64.getDecoder().decode(s);
  }

  public static String bytesToBase64(byte[] b) {
    return Base64.getEncoder().encodeToString(b);
  }
}
