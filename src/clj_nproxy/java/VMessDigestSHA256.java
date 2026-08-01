package clj_nproxy.java;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class VMessDigestSHA256 implements IVMessDigest {
  private final MessageDigest md;

  public VMessDigestSHA256() {
    try {
      md = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private VMessDigestSHA256(MessageDigest md) {
    this.md = md;
  }

  @Override
  public IVMessDigest copy() {
    try {
      return new VMessDigestSHA256((MessageDigest) md.clone());
    } catch (CloneNotSupportedException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void update(byte[] data) {
    md.update(data);
  }

  @Override
  public byte[] digest(byte[] data) {
    return md.digest(data);
  }
}
