package com.example;

import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.Base64;
import java.util.List;

import javax.imageio.ImageIO;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;

@Named
@ApplicationScoped
public class LoginBean {

  private String username;
  private String password;
  private String oneTimePassword;

  public String getOneTimePassword() {
    return oneTimePassword;
  }

  public void setOneTimePassword(String oneTimePassword) {
    this.oneTimePassword = oneTimePassword;
  }

  private String otpAuthURL;
  private String secret;
  private String encodedImage;
  private GoogleAuthenticator gauth;
  private int verificationCode;
  private String now;
  private DateTimeFormatter formatter = new DateTimeFormatterBuilder().appendPattern("HH:mm:ss").toFormatter();

  public String showImage() {

    gauth = new GoogleAuthenticator();
    final GoogleAuthenticatorKey key = gauth.createCredentials();
    this.secret = key.getKey();

    String issuer = "MyIssuer";
    String accountName = "MyAccount";
    this.otpAuthURL = GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(issuer, accountName, key);

    // String url =
    // "otpauth://totp/MyIssuer:MyAccount?secret=YYOLBNJT7GKLOKLLTT47DBPCBO7HMZ3R&issuer=MyIssuer&algorithm=SHA1&digits=6&period=30";
    String url = "otpauth://totp/MyIssuer:MyAccount?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=MyIssuer&algorithm=SHA1&digits=6&period=30";
    this.secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    createQRCodeBase64String(url);

    // デバイス紛失時に利用することを想定したコードを生成
    final List<Integer> scratchCodes = key.getScratchCodes();
    for (Integer i : scratchCodes) {
      System.out.println("Scratch code: " + i);
    }

    System.out.println("Please register (otpauth uri): " + this.otpAuthURL);
    System.out.println("Secret key is " + this.secret);

    return null;
  }

  public void updateVerificationCode() {
    if (gauth != null) {
      this.verificationCode = gauth.getTotpPassword(secret);
      this.now = LocalTime.now().format(formatter);
    }
  }

  private void createQRCodeBase64String(String str) {
    QRCodeWriter qrcodeWriter = new QRCodeWriter();
    try {
      BitMatrix matrix = qrcodeWriter.encode(str, BarcodeFormat.QR_CODE, 300, 300);
      BufferedImage image = MatrixToImageWriter.toBufferedImage(matrix);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      BufferedOutputStream bos = new BufferedOutputStream(baos);
      ImageIO.write(image, "jpg", bos);
      bos.flush();
      byte[] bImage = baos.toByteArray();
      this.encodedImage = Base64.getEncoder().encodeToString(bImage);
      bos.close();
    } catch (IOException | WriterException e) {
      e.printStackTrace();
    }
  }

  public String authenticate() {
    if (gauth != null) {
      boolean authResult = gauth.authorize(secret, Integer.parseInt(oneTimePassword));
      if (authResult) {
        System.out.println("Authentication succeeded");
        return "top?faces-redirect=true";
      }
    }
    return null;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getOtpAuthURL() {
    return otpAuthURL;
  }

  public String getSecret() {
    return secret;
  }

  public void setOtpAuthURL(String otpAuthURL) {
    this.otpAuthURL = otpAuthURL;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public String getEncodedImage() {
    return encodedImage;
  }

  public void setEncodedImage(String encodedImage) {
    this.encodedImage = encodedImage;
  }

  public int getVerificationCode() {
    return verificationCode;
  }

  public void setVerificationCode(int verificationCode) {
    this.verificationCode = verificationCode;
  }

  public String getNow() {
    return now;
  }

  public void setNow(String now) {
    this.now = now;
  }

}
