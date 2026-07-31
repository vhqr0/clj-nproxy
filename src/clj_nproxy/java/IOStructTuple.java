package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public final class IOStructTuple implements IIOStruct<List<Object>> {
  private final List<IIOStruct<Object>> underStructs;
  private final int length;

  public IOStructTuple(List<IIOStruct<Object>> underStructs) {
    this.underStructs = underStructs;
    length = underStructs.size();
  }

  @Override
  public List<Object> read(InputStream is) throws IOException {
    List<Object> data = new ArrayList<>(length);
    for (IIOStruct<Object> underStruct : underStructs) data.add(underStruct.read(is));
    return data;
  }

  @Override
  public void write(OutputStream os, List<Object> data) throws IOException {
    if (data.size() != length) throw new IOStructDataException();
    for (int i = 0; i < length; i++) underStructs.get(i).write(os, data.get(i));
  }
}
