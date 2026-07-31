package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public final class IOStructVarColl implements IIOStruct<List<Object>> {
  private final IIOStruct<Object> underStruct;
  private final IIOStruct<Number> lengthStruct;

  public IOStructVarColl(IIOStruct<Object> underStruct, IIOStruct<Number> lengthStruct) {
    this.underStruct = underStruct;
    this.lengthStruct = lengthStruct;
  }

  @Override
  public List<Object> read(InputStream is) throws IOException {
    int length = Math.toIntExact(lengthStruct.read(is).longValue());
    List<Object> data = new ArrayList<>(length);
    for (int i = 0; i < length; i++) data.add(underStruct.read(is));
    return data;
  }

  @Override
  public void write(OutputStream os, List<Object> data) throws IOException {
    lengthStruct.write(os, Long.valueOf(data.size()));
    for (Object underData : data) underStruct.write(os, underData);
  }
}
