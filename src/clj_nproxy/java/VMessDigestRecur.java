package clj_nproxy.java;

import java.util.Arrays;

public final class VMessDigestRecur implements IVMessDigest {
  private final IVMessDigest inner, outer;

  public VMessDigestRecur(IVMessDigest vd, byte[] key) {
    byte[] ikey = new byte[64];
    byte[] okey = new byte[64];
    Arrays.fill(ikey, (byte) 0x36);
    Arrays.fill(okey, (byte) 0x5c);
    for (int i = 0; i < key.length; i++) {
      int b = key[i];
      ikey[i] = (byte) (0x36 ^ b);
      okey[i] = (byte) (0x5c ^ b);
    }
    inner = vd.copy();
    outer = vd.copy();
    inner.update(ikey);
    outer.update(okey);
  }

  private VMessDigestRecur(IVMessDigest inner, IVMessDigest outer) {
    this.inner = inner;
    this.outer = outer;
  }

  @Override
  public IVMessDigest copy() {
    return new VMessDigestRecur(inner.copy(), outer.copy());
  }

  @Override
  public void update(byte[] data) {
    inner.update(data);
  }

  @Override
  public byte[] digest(byte[] data) {
    return outer.digest(inner.digest(data));
  }
}
