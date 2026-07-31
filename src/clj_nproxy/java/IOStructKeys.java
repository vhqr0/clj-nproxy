package clj_nproxy.java;

import clojure.lang.IFn;
import clojure.lang.IPersistentMap;
import clojure.lang.PersistentArrayMap;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public final class IOStructKeys implements IIOStruct<IPersistentMap> {
  public record KeyStruct(Object key, Object value) {
    @SuppressWarnings("unchecked")
    IIOStruct<Object> getStruct(IPersistentMap data) throws IOStructBaseException {
      if (value instanceof IFn structFn) {
        try {
          return (IIOStruct<Object>) structFn.invoke(data);
        } catch (Exception e) {
          throw new IOStructWrapException(e);
        }
      }
      return (IIOStruct<Object>) value;
    }
  }

  private final List<KeyStruct> underStructs;

  public IOStructKeys(List<KeyStruct> underStructs) {
    this.underStructs = underStructs;
  }

  @Override
  public IPersistentMap read(InputStream is) throws IOException {
    IPersistentMap data = PersistentArrayMap.EMPTY;
    for (KeyStruct underStruct : underStructs)
      data = data.assoc(underStruct.key(), underStruct.getStruct(data).read(is));
    return data;
  }

  @Override
  public void write(OutputStream os, IPersistentMap data) throws IOException {
    for (KeyStruct underStruct : underStructs)
      underStruct.getStruct(data).write(os, data.valAt(underStruct.key()));
  }
}
