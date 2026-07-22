package clj_nproxy.java;

public final class Shake128 {
  private static final int RATE = 168; // (1600 - 2 * 128) / 8

  private static final long[] RC = {
    0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
    0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
    0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
    0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
    0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
    0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
    0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
    0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
  };

  private static final int[] ROT = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
  };

  private static final int[] PILN = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
  };

  private final long[] s = new long[25];
  private int pt = 0;
  private boolean squeezing = false;

  public Shake128(byte[] seed) {
    update(seed, 0, seed.length);
  }

  // Absorb input into the sponge.
  public void update(byte[] in, int off, int len) {
    int j = pt;
    for (int i = 0; i < len; i++) {
      s[j >>> 3] ^= (long) (in[off + i] & 0xff) << (8 * (j & 7));
      if (++j == RATE) {
        keccakf();
        j = 0;
      }
    }
    pt = j;
  }

  // Squeeze len bytes into out[off..off+len). Continues the stream across calls.
  public void doOutput(byte[] out, int off, int len) {
    if (!squeezing) {
      // SHAKE domain separation (0x1F) + pad10*1 (final 0x80)
      s[pt >>> 3] ^= 0x1FL << (8 * (pt & 7));
      s[(RATE - 1) >>> 3] ^= 0x80L << (8 * ((RATE - 1) & 7));
      keccakf();
      pt = 0;
      squeezing = true;
    }
    int j = pt;
    for (int i = 0; i < len; i++) {
      if (j == RATE) {
        keccakf();
        j = 0;
      }
      out[off + i] = (byte) (s[j >>> 3] >>> (8 * (j & 7)));
      j++;
    }
    pt = j;
  }

  private void keccakf() {
    long[] st = s;
    long[] bc = new long[5];
    for (int r = 0; r < 24; r++) {
      // theta
      for (int i = 0; i < 5; i++) {
        bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
      }
      for (int i = 0; i < 5; i++) {
        long t = bc[(i + 4) % 5] ^ Long.rotateLeft(bc[(i + 1) % 5], 1);
        for (int j = 0; j < 25; j += 5) {
          st[j + i] ^= t;
        }
      }
      // rho + pi
      long t = st[1];
      for (int i = 0; i < 24; i++) {
        int j = PILN[i];
        long tmp = st[j];
        st[j] = Long.rotateLeft(t, ROT[i]);
        t = tmp;
      }
      // chi
      for (int j = 0; j < 25; j += 5) {
        for (int i = 0; i < 5; i++) {
          bc[i] = st[j + i];
        }
        for (int i = 0; i < 5; i++) {
          st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
      }
      // iota
      st[0] ^= RC[r];
    }
  }
}
