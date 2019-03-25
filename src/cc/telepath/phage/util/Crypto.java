/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage.util;

import org.bouncycastle.crypto.util.PublicKeyFactory;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
//TODO: REWRITE SIGNATURE STUFF
public class Crypto {

    public Crypto(){
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Returns a base64 encoded 256-bit AES Key
     * @return
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public String generateAESKey() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom sr = new SecureRandom();
        Base64 base64 = new Base64();
        byte[] keyBytes = new byte[32];
        sr.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        return new String(base64.encode(key.getEncoded()));
    }

    /**
     * Encrypt and encode a message with our AES key.
     * @param message
     * @param AESKey
     * @return
     */
    public byte[] AESEncrypt(byte[] message, String AESKey){
        Base64 base64 = new Base64();
        try {
            MessageDigest md = MessageDigest.getInstance("SHA512");
            md.update(base64.decode(AESKey));
            byte[] IV = Arrays.copyOfRange(md.digest(), 0, 16);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            AlgorithmParameterSpec IVSpec = new IvParameterSpec(IV);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(base64.decode(AESKey), "AES"), IVSpec);
            byte[] encryptData = c.doFinal(message);
            return encryptData;
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return null;

    }

    /**
     * Decrypt a message with a given AES key
     * @param message
     * @param AESKey
     * @return
     */
    public byte[] AESDecrypt(byte[] message, String AESKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Base64 base64 = new Base64();
        MessageDigest md = MessageDigest.getInstance("SHA512");
        md.update(base64.decode(AESKey));
        byte[] IV = Arrays.copyOfRange(md.digest(), 0, 16);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        AlgorithmParameterSpec IVSpec = new IvParameterSpec(IV);
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(base64.decode(AESKey), "AES"), IVSpec);
        byte[] decryptData = c.doFinal(message);
        return decryptData;
    }

    /**
     * Returns a 4096-bit RSA keypair for communications.
     * @return
     */
    public KeyPair generateKeypair() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException {
     KeyPairGenerator keyPairGenerator =  KeyPairGenerator.getInstance("RSA", "BC");
     keyPairGenerator.initialize(4096);
     KeyPair k = keyPairGenerator.generateKeyPair();
     return k;
    }

    /**
     * Returns a base64 encoded pair of strings separated by a colon. The first is the encrypted message, the second is
     * the signature of that base64 encoded encrypted message.
     * @param pubkey
     * @param privKey
     * @param message
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws SignatureException
     */
    public String encryptAndSign(PublicKey pubkey, PrivateKey privKey, String message) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException {
        Base64 base64 = new Base64();
        Cipher cipher = Cipher.getInstance(pubkey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);

        byte[] encryptData = cipher.doFinal(message.getBytes());

        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initSign(privKey);
        sig.update(new String(base64.encode(encryptData)).getBytes());
        byte[] signatureBytes = sig.sign();
        String encryptedMessage = new String(base64.encode(encryptData));
        String signature = new String(base64.encode(signatureBytes));
        return encryptedMessage+":"+signature;
    }

    /**
     * Takes a base64 encoded message and decrypts it
     * @param privateKey
     * @param message
     * @return
     */
    public String decryptMessage(PrivateKey privKey, String message) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Base64 base64 = new Base64();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] decryptedBytes = cipher.doFinal(base64.decode(message));
        return new String(decryptedBytes);
    }

    /**
     * Convert an arbitrary length password to a base64 encoded 256-bit AES key.
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public String passwordToAESKey(String password) throws NoSuchAlgorithmException, NoSuchProviderException {
        Base64 base64 = new Base64();
        MessageDigest md = MessageDigest.getInstance("SHA512", "BC");
        md.update(password.getBytes());
        byte[] passwordBytes = Arrays.copyOfRange(md.digest(), 0, 32);
        return new String(base64.encode(passwordBytes));
    }

    /**
     * Returns true if the signature is valid, false if not.
     * @param message
     * @param signature
     * @param pubKey
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public boolean sigValid(String message, String signature, PublicKey pubKey) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
        Signature sig = Signature.getInstance("SHA512withRSA");
        Base64 base64 = new Base64();
        sig.initVerify(pubKey);
        sig.update(message.getBytes());
        return sig.verify(base64.decode(signature));
    }

}
