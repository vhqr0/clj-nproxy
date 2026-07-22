package clj_nproxy.java;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Random;

public final class IOUtils {
  private IOUtils() {}

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

  public static short unpackShortBe(byte[] b) {
    return ByteBuffer.wrap(b).getShort(0);
  }

  public static int unpackIntBe(byte[] b) {
    return ByteBuffer.wrap(b).getInt(0);
  }

  public static long unpackLongBe(byte[] b) {
    return ByteBuffer.wrap(b).getLong(0);
  }

  public static float unpackFloatBe(byte[] b) {
    return ByteBuffer.wrap(b).getFloat(0);
  }

  public static double unpackDoubleBe(byte[] b) {
    return ByteBuffer.wrap(b).getDouble(0);
  }

  public static short unpackShortLe(byte[] b) {
    return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getShort(0);
  }

  public static int unpackIntLe(byte[] b) {
    return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
  }

  public static long unpackLongLe(byte[] b) {
    return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getLong(0);
  }

  public static float unpackFloatLe(byte[] b) {
    return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getFloat(0);
  }

  public static double unpackDoubleLe(byte[] b) {
    return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getDouble(0);
  }

  public static byte[] packShortBe(long v) {
    return ByteBuffer.allocate(2).putShort((short) v).array();
  }

  public static byte[] packIntBe(long v) {
    return ByteBuffer.allocate(4).putInt((int) v).array();
  }

  public static byte[] packLongBe(long v) {
    return ByteBuffer.allocate(8).putLong(v).array();
  }

  public static byte[] packFloatBe(double v) {
    return ByteBuffer.allocate(4).putFloat((float) v).array();
  }

  public static byte[] packDoubleBe(double v) {
    return ByteBuffer.allocate(8).putDouble(v).array();
  }

  public static byte[] packShortLe(long v) {
    return ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) v).array();
  }

  public static byte[] packIntLe(long v) {
    return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) v).array();
  }

  public static byte[] packLongLe(long v) {
    return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array();
  }

  public static byte[] packFloatLe(double v) {
    return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putFloat((float) v).array();
  }

  public static byte[] packDoubleLe(double v) {
    return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putDouble(v).array();
  }

  public static int unpackUshortBe(byte[] b) {
    return unpackShortBe(b) & 0xffff;
  }

  public static int unpackUshortLe(byte[] b) {
    return unpackShortLe(b) & 0xffff;
  }

  public static long unpackUintBe(byte[] b) {
    return unpackIntBe(b) & 0xffffffffL;
  }

  public static long unpackUintLe(byte[] b) {
    return unpackIntLe(b) & 0xffffffffL;
  }

  public static byte[] packUshortBe(long v) {
    return packShortBe(v);
  }

  public static byte[] packUshortLe(long v) {
    return packShortLe(v);
  }

  public static byte[] packUintBe(long v) {
    return packIntBe(v);
  }

  public static byte[] packUintLe(long v) {
    return packIntLe(v);
  }
}
