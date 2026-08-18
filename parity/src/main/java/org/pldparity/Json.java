package org.pldparity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader/writer so the generator carries no dependency beyond the helpers library.
 *
 * <p>Parses into {@link Map}, {@link List}, {@link String}, {@link Double}, {@link Boolean} and
 * null. Writes those same shapes, escaping every non-ASCII character as {@code \\uXXXX} so the
 * output is pure ASCII regardless of the consumer's encoding assumptions.
 */
final class Json {

  static Object parse(String text) {
    Parser parser = new Parser(text);
    parser.skipWhitespace();
    Object value = parser.value();
    parser.skipWhitespace();
    if (!parser.done()) {
      throw new IllegalArgumentException("trailing content at offset " + parser.position);
    }
    return value;
  }

  static String write(Object value) {
    StringBuilder builder = new StringBuilder();
    writeValue(value, builder, 0);
    return builder.toString();
  }

  private static void writeValue(Object value, StringBuilder builder, int depth) {
    if (value instanceof String) {
      writeString((String) value, builder);
    } else if (value instanceof Map) {
      writeObject((Map<?, ?>) value, builder, depth);
    } else if (value instanceof List) {
      writeArray((List<?>) value, builder, depth);
    } else if (value instanceof Number || value instanceof Boolean) {
      builder.append(value);
    } else if (value == null) {
      builder.append("null");
    } else {
      throw new IllegalArgumentException("unsupported JSON value: " + value.getClass());
    }
  }

  private static void writeObject(Map<?, ?> map, StringBuilder builder, int depth) {
    if (map.isEmpty()) {
      builder.append("{}");
      return;
    }
    builder.append("{\n");
    boolean first = true;
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!first) {
        builder.append(",\n");
      }
      first = false;
      indent(builder, depth + 1);
      writeString(String.valueOf(entry.getKey()), builder);
      builder.append(": ");
      writeValue(entry.getValue(), builder, depth + 1);
    }
    builder.append('\n');
    indent(builder, depth);
    builder.append('}');
  }

  private static void writeArray(List<?> list, StringBuilder builder, int depth) {
    if (list.isEmpty()) {
      builder.append("[]");
      return;
    }
    builder.append("[\n");
    boolean first = true;
    for (Object element : list) {
      if (!first) {
        builder.append(",\n");
      }
      first = false;
      indent(builder, depth + 1);
      writeValue(element, builder, depth + 1);
    }
    builder.append('\n');
    indent(builder, depth);
    builder.append(']');
  }

  private static void indent(StringBuilder builder, int depth) {
    for (int i = 0; i < depth; i++) {
      builder.append("  ");
    }
  }

  private static void writeString(String value, StringBuilder builder) {
    builder.append('"');
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"' -> builder.append("\\\"");
        case '\\' -> builder.append("\\\\");
        case '\n' -> builder.append("\\n");
        case '\r' -> builder.append("\\r");
        case '\t' -> builder.append("\\t");
        case '\b' -> builder.append("\\b");
        case '\f' -> builder.append("\\f");
        default -> {
          if (c < 0x20 || c > 0x7E) {
            builder.append(String.format("\\u%04x", (int) c));
          } else {
            builder.append(c);
          }
        }
      }
    }
    builder.append('"');
  }

  private static final class Parser {
    private final String text;
    private int position;

    Parser(String text) {
      this.text = text;
    }

    boolean done() {
      return position >= text.length();
    }

    void skipWhitespace() {
      while (position < text.length() && Character.isWhitespace(text.charAt(position))) {
        position++;
      }
    }

    Object value() {
      char c = peek();
      return switch (c) {
        case '{' -> object();
        case '[' -> array();
        case '"' -> string();
        case 't' -> literal("true", Boolean.TRUE);
        case 'f' -> literal("false", Boolean.FALSE);
        case 'n' -> literal("null", null);
        default -> number();
      };
    }

    private Map<String, Object> object() {
      expect('{');
      Map<String, Object> map = new LinkedHashMap<>();
      skipWhitespace();
      if (peek() == '}') {
        position++;
        return map;
      }
      while (true) {
        skipWhitespace();
        String key = string();
        skipWhitespace();
        expect(':');
        skipWhitespace();
        map.put(key, value());
        skipWhitespace();
        char c = next();
        if (c == '}') {
          return map;
        }
        if (c != ',') {
          throw new IllegalArgumentException("expected ',' or '}' at offset " + (position - 1));
        }
      }
    }

    private List<Object> array() {
      expect('[');
      List<Object> list = new ArrayList<>();
      skipWhitespace();
      if (peek() == ']') {
        position++;
        return list;
      }
      while (true) {
        skipWhitespace();
        list.add(value());
        skipWhitespace();
        char c = next();
        if (c == ']') {
          return list;
        }
        if (c != ',') {
          throw new IllegalArgumentException("expected ',' or ']' at offset " + (position - 1));
        }
      }
    }

    private String string() {
      expect('"');
      StringBuilder builder = new StringBuilder();
      while (true) {
        char c = next();
        if (c == '"') {
          return builder.toString();
        }
        if (c != '\\') {
          builder.append(c);
          continue;
        }
        char escape = next();
        switch (escape) {
          case '"' -> builder.append('"');
          case '\\' -> builder.append('\\');
          case '/' -> builder.append('/');
          case 'b' -> builder.append('\b');
          case 'f' -> builder.append('\f');
          case 'n' -> builder.append('\n');
          case 'r' -> builder.append('\r');
          case 't' -> builder.append('\t');
          case 'u' -> {
            builder.append((char) Integer.parseInt(text.substring(position, position + 4), 16));
            position += 4;
          }
          default -> throw new IllegalArgumentException("bad escape '\\" + escape + "'");
        }
      }
    }

    private Object literal(String word, Object result) {
      if (!text.startsWith(word, position)) {
        throw new IllegalArgumentException("expected '" + word + "' at offset " + position);
      }
      position += word.length();
      return result;
    }

    private Double number() {
      int start = position;
      while (position < text.length() && "-+.eE0123456789".indexOf(text.charAt(position)) >= 0) {
        position++;
      }
      if (start == position) {
        throw new IllegalArgumentException("unexpected character at offset " + position);
      }
      return Double.valueOf(text.substring(start, position));
    }

    private char peek() {
      if (done()) {
        throw new IllegalArgumentException("unexpected end of input");
      }
      return text.charAt(position);
    }

    private char next() {
      char c = peek();
      position++;
      return c;
    }

    private void expect(char expected) {
      char c = next();
      if (c != expected) {
        throw new IllegalArgumentException(
            "expected '" + expected + "' but found '" + c + "' at offset " + (position - 1));
      }
    }
  }

  private Json() {}
}
