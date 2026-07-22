package clj_nproxy.java;

import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletionStage;

public class QueuedWebSocketListener implements WebSocket.Listener {
  public record Message(Object data, boolean last) {}

  public static final Message EOF = new Message(null, true);

  BlockingQueue<Message> queue;

  public QueuedWebSocketListener(BlockingQueue<Message> queue) {
    this.queue = queue;
  }

  private void shutdown() {
    if (!queue.offer(EOF)) {
      queue.clear();
      queue.offer(EOF);
    }
  }

  @Override
  public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
    Message message = new Message(data.toString(), last);
    if (queue.offer(message)) {
      webSocket.request(1);
    } else {
      webSocket.abort();
    }
    return null;
  }

  @Override
  public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
    byte[] dataBytes = new byte[data.remaining()];
    data.get(dataBytes);
    Message message = new Message(dataBytes, last);
    if (queue.offer(message)) {
      webSocket.request(1);
    } else {
      webSocket.abort();
    }
    return null;
  }

  @Override
  public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
    shutdown();
    return null;
  }

  @Override
  public void onError(WebSocket webSocket, Throwable error) {
    shutdown();
  }
}
