package com.example;

import java.util.List;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;

@Named
@RequestScoped
public class GoogleAuthExample {

  private String otpAuthURL;
  private String secret;

  public void authenticate() {

    GoogleAuthenticator gauth = new GoogleAuthenticator();
    final GoogleAuthenticatorKey key = gauth.createCredentials();
    final String secret = key.getKey();
    final List<Integer> scratchCodes = key.getScratchCodes();

    String otpAuthURL = GoogleAuthenticatorQRGenerator.getOtpAuthURL("Test Org.", "test@prova.org", key);

    for (Integer i : scratchCodes) {
      System.out.println("Scratch code: " + i);
    }

    this.otpAuthURL = otpAuthURL;
    this.secret = secret;

    System.out.println("Please register (otpauth uri): " + this.otpAuthURL);
    System.out.println("Secret key is " + this.secret);
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

}
