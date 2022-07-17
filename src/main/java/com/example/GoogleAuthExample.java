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

  public void authenticate() {
    GoogleAuthenticator gauth = new GoogleAuthenticator();
    final GoogleAuthenticatorKey key = gauth.createCredentials();
    final String secret = key.getKey();
    final List<Integer> scratchCodes = key.getScratchCodes();
    String otpAuthURL = GoogleAuthenticatorQRGenerator.getOtpAuthURL("Test Org.", "test@prova.org", key);

    System.out.println("Please register (otpauth uri): " + otpAuthURL);
    System.out.println("Secret key is " + secret);
  }
}
