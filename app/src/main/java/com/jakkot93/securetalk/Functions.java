package com.jakkot93.securetalk;


import android.util.Log;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by Jakkot93 on 2015-12-10.
 */
public class Functions {

    private static final String TAG = "JK93";

    //Create RSA (1024) KeyPair
    public KeyPair GenerateKeyRSA (){
        KeyPair kp = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            kp = kpg.genKeyPair();
        } catch (Exception e) {
            Log.e(TAG, "RSA key pair error");
            e.printStackTrace();
        }
        return kp;
    }

    //Create AES (256) Key
    public SecretKey GenerateKeyAES (String msg){
        SecretKey SecretKeyAES = null;
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(msg.getBytes());
            kgen.init(256, sr);
            SecretKeyAES = kgen.generateKey();
        } catch (Exception e) {
            Log.e(TAG, "AES key error");
            e.printStackTrace();
        }
        return SecretKeyAES;
    }

    //Save RSA Public Key
    public PublicKey DownloadedPublicKey(byte[] msg){
        PublicKey ClientPublicKey = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(msg);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            ClientPublicKey = keyFactory.generatePublic(spec);
        } catch (Exception e) {
            Log.e(TAG, "RSA Public error");
            e.printStackTrace();
        }
        return ClientPublicKey;
    }

    //Decryption AES
    public byte[] DecryptionAES(byte[] msg, SecretKey SecretKeyAES){
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, SecretKeyAES);
            decrypted = cipher.doFinal(msg);
        }
        catch (Exception e){
            Log.e(TAG, "AES DECRYPT error");
            e.printStackTrace();
        }
        return decrypted;
    }

    //Encryption AES
    public byte[] EncryptionAES(byte[] msg, SecretKey SecretKeyAES){
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyAES);
            encrypted = cipher.doFinal(msg);
        }
        catch (Exception e){
            Log.e(TAG, "AES ENCRYPT error");
            e.printStackTrace();
        }
        return encrypted;
    }

    //Decryption RSA
    public byte[] DecryptionRSA(byte[] msg, Key KeyRSA){
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, KeyRSA);
            decrypted = cipher.doFinal(msg);
        }
        catch (Exception e){
            Log.e(TAG, "RSA DECRYPT error");
            e.printStackTrace();
        }
        return decrypted;
    }

    //Encryption RSA
    public byte[] EncryptionRSA(byte[] msg, Key KeyRSA){
        byte[] encrypted = null;
        try {
            //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, KeyRSA);
            encrypted = cipher.doFinal(msg);
        }
        catch (Exception e){
            Log.e(TAG, "RSA ENCRYPT error");
            e.printStackTrace();
        }
        return encrypted;
    }

    //Create Digest
    public String DigestFromMsg(byte[] msg) {
        MessageDigest digest;
        byte[] hash = null;

        try {
            digest = MessageDigest.getInstance("SHA-256");
            digest.update(msg);
            hash = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            Log.e(TAG, "DIGEST error");
            e.printStackTrace();
        }
        StringBuilder buf = new StringBuilder();
        for (byte b : hash) {
            int halfbyte = (b >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                buf.append((0 <= halfbyte) && (halfbyte <= 9) ? (char) ('0' + halfbyte) : (char) ('a' + (halfbyte - 10)));
                halfbyte = b & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    //Check IP Address
    public String getIpAddress() {
        String ip = "";
        try {
            Enumeration<NetworkInterface> enumNetworkInterfaces = NetworkInterface
                    .getNetworkInterfaces();
            while (enumNetworkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = enumNetworkInterfaces
                        .nextElement();
                Enumeration<InetAddress> enumInetAddress = networkInterface
                        .getInetAddresses();
                while (enumInetAddress.hasMoreElements()) {
                    InetAddress inetAddress = enumInetAddress.nextElement();

                    if (inetAddress.isSiteLocalAddress()) {
                        ip += "Address IP: "
                                + inetAddress.getHostAddress() + "\n";
                    }
                }
            }
        } catch (SocketException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            ip += "Something Wrong! " + e.toString() + "\n";
        }
        return ip;
    }

    //Signature Message
    public byte[] Signed(byte[] msg, PrivateKey Key){
        byte[] sign = null;
        try {
            Signature s = Signature.getInstance("SHA1withRSA");
            s.initSign(Key);
            s.update(msg);
            sign = s.sign();
        }catch (Exception e){
            e.printStackTrace();
        }
        return sign;
    }

    //Signature Verification
    public boolean Verify(byte[] msg, PublicKey Key, byte[] sign){
        boolean IsVerify = true;
        try {
            Signature s = Signature.getInstance("SHA1withRSA");
            s.initVerify(Key);
            s.update(msg);
            IsVerify = s.verify(sign);
        }catch (Exception e){
            e.printStackTrace();
        }
        return IsVerify;
    }

    //Decryption RSA with Android KeyStore
    public byte[] DecryptionRSAAndroidKS(byte[] msg, Key KeyRSA){
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            cipher.init(Cipher.DECRYPT_MODE, KeyRSA);
            decrypted = cipher.doFinal(msg);
        }
        catch (Exception e){
            Log.e(TAG, "RSA DECRYPT KS error");
            e.printStackTrace();
        }
        return decrypted;
    }

    //Encryption RSA with Android KeyStore
    public byte[] EncryptionRSAAndroidKS(byte[] msg, Key KeyRSA){
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            cipher.init(Cipher.ENCRYPT_MODE, KeyRSA);
            encrypted = cipher.doFinal(msg);
        }
        catch (Exception e){
            Log.e(TAG, "RSA ENCRYPT KS error");
            e.printStackTrace();
        }
        return encrypted;
    }
}
