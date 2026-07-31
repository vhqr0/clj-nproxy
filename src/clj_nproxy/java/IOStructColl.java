package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public final class IOStructColl implements IIOStruct<List<Object>> {
  private final IIOStruct<Object> underStruct;
  private final int length;

  public IOStructColl(IIOStruct<Object> underStruct, int length) {
    this.underStruct = underStruct;
    this.length = length;
  }

  @Override
  public List<Object> read(InputStream is) throws IOException {
    List<Object> data = new ArrayList<>(length);
    for (int i = 0; i < length; i++) data.add(underStruct.read(is));
    return data;
  }

  @Override
  public void write(OutputStream os, List<Object> data) throws IOException {
    if (data.size() != length) throw new IOStructDataException();
    for (Object underData : data) underStruct.write(os, underData);
  }
}
