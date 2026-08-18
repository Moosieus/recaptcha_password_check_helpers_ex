package org.pldparity;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.cloud.recaptcha.passwordcheck.utils.BCScryptGenerator;
import com.google.cloud.recaptcha.passwordcheck.utils.CryptoHelper;
import com.google.cloud.recaptcha.passwordcheck.utils.ScryptGenerator;
import com.google.cloud.recaptcha.passwordcheck.utils.SensitiveString;
import com.google.privacy.encryption.commutative.EcCommutativeCipher;
import com.google.privacy.encryption.commutative.SupportedCurve;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Emits byte-exact test vectors from Google's recaptcha-password-check-helpers library.
 *
 * <p>Reads a JSON array of inputs from stdin and writes a JSON object to stdout. Every EC private
 * key comes from the input, so runs are fully deterministic.
 */
public final class VectorGen {

  private static final String HELPERS_VERSION = "1.0.10";

  /** Bit length of the username hash prefix expected by the reCAPTCHA leak-check service. */
  private static final int USERNAME_HASH_PREFIX_LENGTH = 26;

  /** Byte length of the leak-match prefixes the service returns. */
  private static final int LEAK_MATCH_PREFIX_LENGTH = 20;

  private static final ScryptGenerator SCRYPT = new BCScryptGenerator();

  public static void main(String[] args) throws IOException {
    List<?> inputs = (List<?>) Json.parse(readAll(System.in));

    List<Map<String, String>> vectors = new ArrayList<>();
    for (Object input : inputs) {
      vectors.add(vector((Map<?, ?>) input));
    }

    Map<String, Object> output = new LinkedHashMap<>();
    output.put("helpers_version", HELPERS_VERSION);
    output.put("vectors", vectors);

    PrintStream out = new PrintStream(System.out, false, UTF_8);
    out.print(Json.write(output));
    out.println();
    out.flush();
  }

  private static Map<String, String> vector(Map<?, ?> input) {
    String username = (String) input.get("username");
    String password = (String) input.get("password");
    String clientKeyHex = (String) input.get("client_private_key_hex");
    String serverKeyHex = (String) input.get("server_private_key_hex");

    EcCommutativeCipher client =
        EcCommutativeCipher.createFromKey(SupportedCurve.SECP256R1, fromHex(clientKeyHex));
    EcCommutativeCipher server =
        EcCommutativeCipher.createFromKey(SupportedCurve.SECP256R1, fromHex(serverKeyHex));

    String canonicalized = CryptoHelper.canonicalizeUsername(username);
    byte[] usernameHash = CryptoHelper.hashUsername(canonicalized);
    byte[] lookupHashPrefix =
        CryptoHelper.bucketizeUsername(canonicalized, USERNAME_HASH_PREFIX_LENGTH);
    byte[] credentialsHash =
        CryptoHelper.hashUsernamePasswordPair(
            canonicalized, SensitiveString.of(password), SCRYPT);

    byte[] hashIntoCurve = client.hashIntoTheCurve(credentialsHash);
    byte[] encryptedCredentialsHash = client.encrypt(credentialsHash);
    byte[] serverReencrypted = server.reEncrypt(encryptedCredentialsHash);
    byte[] clientDecrypted = client.decrypt(serverReencrypted);
    byte[] rehashedDecrypted = CryptoHelper.hashBlindedHash(clientDecrypted);

    byte[] serverEncrypted = server.encrypt(credentialsHash);
    byte[] serverMatchPrefix =
        Arrays.copyOf(sha256(serverEncrypted), LEAK_MATCH_PREFIX_LENGTH);

    // The whole protocol rests on commutativity: decrypt(reEncrypt(encrypt(h))) with the client
    // key must equal the server's own encrypt(h). Fail loudly rather than emit a bad vector.
    if (!Arrays.equals(clientDecrypted, serverEncrypted)) {
      throw new IllegalStateException(
          "commutativity broken for username=" + username + ": " + toHex(clientDecrypted)
              + " != " + toHex(serverEncrypted));
    }
    if (!Arrays.equals(Arrays.copyOf(rehashedDecrypted, LEAK_MATCH_PREFIX_LENGTH), serverMatchPrefix)) {
      throw new IllegalStateException("prefix match broken for username=" + username);
    }

    Map<String, String> vector = new LinkedHashMap<>();
    vector.put("username", username);
    vector.put("password", password);
    vector.put("client_private_key_hex", clientKeyHex);
    vector.put("server_private_key_hex", serverKeyHex);
    vector.put("canonicalized_username", canonicalized);
    vector.put("username_hash_hex", toHex(usernameHash));
    vector.put("lookup_hash_prefix_hex", toHex(lookupHashPrefix));
    vector.put("credentials_hash_hex", toHex(credentialsHash));
    vector.put("hash_into_curve_hex", toHex(hashIntoCurve));
    vector.put("encrypted_credentials_hash_hex", toHex(encryptedCredentialsHash));
    vector.put("server_reencrypted_hex", toHex(serverReencrypted));
    vector.put("client_decrypted_hex", toHex(clientDecrypted));
    vector.put("rehashed_decrypted_hex", toHex(rehashedDecrypted));
    vector.put("server_match_prefix_hex", toHex(serverMatchPrefix));
    return vector;
  }

  private static byte[] sha256(byte[] bytes) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private static String readAll(InputStream in) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    byte[] chunk = new byte[8192];
    int read;
    while ((read = in.read(chunk)) != -1) {
      buffer.write(chunk, 0, read);
    }
    return new String(buffer.toByteArray(), UTF_8);
  }

  private static byte[] fromHex(String hex) {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("odd-length hex string: " + hex);
    }
    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private static String toHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      builder.append(Character.forDigit((b >> 4) & 0xF, 16));
      builder.append(Character.forDigit(b & 0xF, 16));
    }
    return builder.toString();
  }

  private VectorGen() {}
}
