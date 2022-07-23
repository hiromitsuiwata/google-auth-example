package com.example;

import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * rfc6238のコードを抜粋して一部変更
 * https://tex2e.github.io/rfc-translater/html/rfc6238.html
 * https://datatracker.ietf.org/doc/html/rfc6238
 */
public class TOTP {

  private static final Logger logger = LoggerFactory.getLogger(TOTP.class);

  private TOTP() {
    // private constructor to prevent instantiation
  }

  /**
   * This method uses the JCE to provide the crypto algorithm.
   * HMAC computes a Hashed Message Authentication Code with the
   * crypto hash algorithm as a parameter.
   *
   * @param crypto:   the crypto algorithm (HmacSHA1, HmacSHA256,
   *                  HmacSHA512)
   * @param keyBytes: the bytes to use for the HMAC key
   * @param text:     the message or text to be authenticated
   */
  private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {
    try {
      Mac hmac;
      hmac = Mac.getInstance(crypto);
      // SecretKeySpecは指定された鍵素材とアルゴリズムから秘密鍵を生成するが
      // ここでは鍵素材をそのまま使ってよい。秘密鍵を外部から与えてGoogle AuthenticatorへQRコード経由で渡すため
      SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
      hmac.init(macKey);
      // 指定された秘密鍵(hmac, keyBytes)を使ってtextのメッセージ認証コードを作成する
      return hmac.doFinal(text);
    } catch (GeneralSecurityException gse) {
      throw new UndeclaredThrowableException(gse);
    }
  }

  /**
   * This method converts a HEX string to Byte[]
   *
   * @param hex: the HEX string
   *
   * @return: a byte array
   */
  private static byte[] hexStr2Bytes(String hex) {
    // Adding one byte to get the right conversion
    // Values starting with "0" can be converted
    byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

    // Copy all the REAL bytes, not the "first"
    byte[] ret = new byte[bArray.length - 1];
    for (int i = 0; i < ret.length; i++)
      ret[i] = bArray[i + 1];
    return ret;
  }

  private static final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000 };

  /**
   * This method generates a TOTP value for the given
   * set of parameters.
   *
   * @param key:          the shared secret, HEX encoded
   * @param time:         a value that reflects a time
   * @param returnDigits: number of digits to return
   * @param crypto:       the crypto function to use
   *
   * @return: a numeric String in base 10 that includes
   *          {@link truncationDigits} digits
   */
  public static String generateTOTP(String key,
      String time,
      String returnDigits,
      String crypto) {
    int codeDigits = Integer.decode(returnDigits).intValue();
    String result = null;

    // このロジックの中で可変なのは実質的にtimeのみ。

    // Using the counter
    // First 8 bytes are for the movingFactor
    // Compliant with base RFC 4226 (HOTP)
    while (time.length() < 16) {
      time = "0" + time;
    }

    // Get the HEX in a Byte[]
    byte[] msg = hexStr2Bytes(time);
    byte[] k = hexStr2Bytes(key);

    byte[] hash = hmac_sha(crypto, k, msg);

    // put selected bytes into result int
    int offset = hash[hash.length - 1] & 0xf;

    int binary = ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    // 出てきた値を非負の整数だとみなして、6桁の認証コードを作る場合は1,000,000で割った余りを計算する
    int otp = binary % DIGITS_POWER[codeDigits];

    // 所定の桁数になるまで0埋め
    result = Integer.toString(otp);
    while (result.length() < codeDigits) {
      result = "0" + result;
    }

    return result;
  }

  public static void main(String[] args) {

    // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    // Google AuthenticatorはBase32, Sha1, 6桁のOTP, 30秒間隔がデフォルトなのでそれに合わせる

    // Seed for HMAC-SHA1 - 20 bytes
    // SHA1は20バイトのハッシュ値を返すのでそれに合わせている
    // 実際はSecureRandomなどで20バイトの乱数を生成する
    String seed = "3132333435363738393031323334353637383930";
    byte[] k = hexStr2Bytes(seed);
    String base32K = new Base32().encodeToString(k);
    // QRコードを生成する時に使うのはこのBase32でエンコードした文字列
    logger.info("secret key(Base32 encoded): {}, byte length: {}", base32K, k.length);

    long initialCounterTimeT0 = 0;
    long timeStepX = 30;

    // 現在時刻から30秒間隔でOTPを生成する
    long now = ZonedDateTime.now(ZoneOffset.UTC).toEpochSecond();
    long[] testTime = { now, now + 30L, now + 60L, now + 90L, now + 120L, now + 150L, now + 180L };

    String steps = "0";
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    df.setTimeZone(TimeZone.getTimeZone("UTC"));

    try {
      for (int i = 0; i < testTime.length; i++) {
        long T = (testTime[i] - initialCounterTimeT0) / timeStepX;
        steps = Long.toHexString(T).toUpperCase();
        while (steps.length() < 16) {
          steps = "0" + steps;
        }

        String utcTime = df.format(new Date(testTime[i] * 1000));
        logger.info("testTime(UTC): {}, TOTP: {}", utcTime, generateTOTP(seed, steps, "6", "HmacSHA1"));

        // TOTP方式はサーバーとデバイスの時計が一致していないと問題となる
        // 検証時は何秒以内の時間のずれなら許容するかを考慮するべき
        // 例えば前後30秒ずれた（つまり前後1つ分ずれた）認証コード許容するなど

        // 例えば1回分過去にずれた認証コードを受け取り、認証に成功と判断した場合、
        // クライアントは30秒過去にずれた時計を持っていると推測される。サーバー側でこの事実を記憶しておき
        // 次回のログイン時には30秒過去にずれた時点を基準に前後30秒ずつずれた（つまり前後1つ分ずれた）ものを許容する
        // ようにしておくと、時刻が少しずつずれていくことをを許容することができる（再同期）
        // RFCとしてはRECOMMEND となっている
        // Google Authenticator等を使う場合デバイスの時刻のずれはほぼないものとしてよさそう。
        // Authy, Duo Mobile, LastPass Authenticator, Microsoft Authenticator, Google
        // Authenticator, Symantec VIP等のどれでテストをするか

        // ただし上記の再同期は、こまめにログインを繰り返す場合には有効だが、少しずつ時計がずれていくデバイスを利用して
        // 長期間（たとえば1年）一度もログインせず何分も時計がずれてしまうと、再同期の範囲を超えて二度とログインできなくなる恐れがある
        // その場合に備えて追加の認証手段を用意しておく必要がある。

        // 別の手段でいったんMFAを無効化するなどが手軽か。

        // 一度検証が成功したら、その認証コードを再度送ってきた場合には拒否する必要がある（再生攻撃対策）

        // https://manpages.debian.org/testing/libpam-google-authenticator/google-authenticator.1.en.html
        // https://tex2e.github.io/rfc-translater/html/rfc6238.html
      }
    } catch (final Exception e) {
      e.printStackTrace();
    }
  }
}
