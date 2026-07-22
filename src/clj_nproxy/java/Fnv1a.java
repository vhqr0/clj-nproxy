package clj_nproxy.java;

public final class Fnv1a {
  private Fnv1a() {}

  private static final int OFFSET_BASIS = 0x811c9dc5;
  private static final int PRIME = 0x01000193;

  public static byte[] hash(byte[] b) {
    int h = OFFSET_BASIS;
    for (byte x : b) {
      h = (h ^ (x & 0xff)) * PRIME;
    }
    return new byte[] {(byte) (h >>> 24), (byte) (h >>> 16), (byte) (h >>> 8), (byte) h};
  }
}
