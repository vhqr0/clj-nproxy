package clj_nproxy.java;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructDelimitedBytes implements IIOStruct<byte[]> {
  private final byte[] delim;

  public IOStructDelimitedBytes(byte[] delim) {
    this.delim = delim;
  }

  @Override
  public byte[] read(InputStream is) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    int delimLength = delim.length;
    byte[] pb = is.readNBytes(delimLength);
    if (pb.length != delimLength) throw new IOStructEOFException();
    while (IOUtils.compare(pb, delim) != 0) {
      baos.write(pb[0]);
      int n = is.read();
      if (n == -1) throw new IOStructEOFException();
      byte[] npb = new byte[delimLength];
      IOUtils.copy(pb, 1, npb, 0, delimLength - 1);
      npb[delimLength - 1] = (byte) n;
      pb = npb;
    }
    return baos.toByteArray();
  }

  @Override
  public void write(OutputStream os, byte[] data) throws IOException {
    os.write(data);
    os.write(delim);
  }
}
