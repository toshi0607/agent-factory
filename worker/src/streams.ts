export class BodyTooLarge extends Error {}
export const MAX_UPLOAD_BYTES = 95 * 1024 * 1024;

export async function readBytes(body: ReadableStream<Uint8Array> | null, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  let bytes = new Uint8Array();
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      const nextSize = size + part.value.byteLength;
      if (nextSize > limit) throw new BodyTooLarge();
      if (nextSize > bytes.byteLength) {
        const expanded = new Uint8Array(Math.min(limit, Math.max(nextSize, bytes.byteLength * 2, 1024)));
        expanded.set(bytes.subarray(0, size));
        bytes = expanded;
      }
      bytes.set(part.value, size);
      size = nextSize;
    }
  } catch (error) {
    void reader.cancel().catch(() => console.warn({ event: "stream_cancel_failed" }));
    throw error;
  } finally {
    reader.releaseLock();
  }
  return bytes.subarray(0, size);
}

// An oversized line is reported as null. CR, LF and CRLF may straddle chunks.
export async function* readLines(
  body: ReadableStream<Uint8Array>, limit: number, fatal = false,
): AsyncGenerator<string | null> {
  const decoder = new TextDecoder("utf-8", { fatal, ignoreBOM: false });
  const reader = body.getReader();
  let line = "";
  let overflow = false;
  let afterCr = false;
  let complete = false;

  function* consume(text: string): Generator<string | null> {
    if (!text) return;
    let start = afterCr && text[0] === "\n" ? 1 : 0;
    afterCr = false;
    const endings = /\r\n|\n|\r/g;
    endings.lastIndex = start;
    for (let match = endings.exec(text); match; match = endings.exec(text)) {
      const length = match.index - start;
      yield overflow || line.length + length > limit ? null : line + text.slice(start, match.index);
      line = "";
      overflow = false;
      start = endings.lastIndex;
      afterCr = start === text.length && match[0] === "\r";
    }
    if (line.length + text.length - start > limit) {
      overflow = true;
      line = "";
    } else if (!overflow) {
      line += text.slice(start);
    }
  }

  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      yield* consume(decoder.decode(part.value, { stream: true }));
    }
    complete = true;
    yield* consume(decoder.decode());
    if (overflow || line.length) yield overflow ? null : line;
  } finally {
    if (!complete) void reader.cancel().catch(() => console.warn({ event: "stream_cancel_failed" }));
    reader.releaseLock();
  }
}
