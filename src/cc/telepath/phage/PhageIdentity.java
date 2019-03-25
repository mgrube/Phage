/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

import cc.telepath.phage.util.Crypto;
import net.pterodactylus.fcp.highlevel.FcpException;

import org.apache.commons.lang.RandomStringUtils;
import org.bouncycastle.jcajce.provider.symmetric.ARC4;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;

public class PhageIdentity implements Serializable {

    private PublicKey pubKey;
    private PrivateKey privkey;
    private String freenetPubkey;
    private String freenetPrivkey;
    private String contactChannel;
    private HashMap<String, String> privateChannels;


    public PhageIdentity(PublicKey PublicKey, PrivateKey PrivateKey, String FreenetPublicKey, String FreenetPrivateKey, String ContactChannel) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Base64 base64 = new Base64();
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        this.pubKey = PublicKey;
        if(PrivateKey != null) {
            this.privkey = PrivateKey;
        }
        this.freenetPubkey = FreenetPublicKey;
        if(FreenetPrivateKey != null){
            this.freenetPrivkey = FreenetPrivateKey;
        }
        if(ContactChannel != null){
            this.contactChannel = ContactChannel;
        }
    }

    public PhageIdentity(PublicKey pubkey, PrivateKey privkey, String freenetPubkey, String freenetPrivkey){
        this.pubKey = pubkey;
        this.privkey = privkey;
        this.freenetPrivkey = freenetPrivkey;
        this.freenetPubkey = freenetPubkey;
    }

    public PhageIdentity(PublicKey pubkey, String freenetPubkey){
        this.pubKey = pubkey;
        this.freenetPubkey = freenetPubkey;
        privkey = null;
        freenetPrivkey = null;
    }

    /**
     * @param pubkey - A Base64 encoded 2048 bit X509 Public Key
     * @param freenetPubkey - A Freenet public key at which to retrieve messages
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public PhageIdentity(String pubkey, String freenetPubkey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Base64 base64 = new Base64();
        byte[] b = base64.decode(pubkey.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        this.pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(b));
        this.freenetPubkey = freenetPubkey;
    }

    /**
     *
     * @param PhageGroupPubKey
     * @param pcl
     */
    public void annouceKeys(String PhageGroupPubKey, PhageFCPClient pcl){
        Base64 base64 = new Base64();
        Crypto c = new Crypto();

    }



    /**
     * Discover a secret channel that has been announced to our key.
     * @param PhageGroupPubKey
     * @param pcl
     * @return
     * @throws IOException
     * @throws FcpException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void discoverSecretChannel(String PhageGroupPubKey, PhageFCPClient pcl) throws InvalidSigException, IOException, FcpException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        Base64 base64 = new Base64();
        Hex hex =  new Hex();
        Crypto c = new Crypto();
        String ownkey = new String(base64.encode(this.pubKey.getEncoded()));
        String combination;
        if(PhageGroupPubKey.compareTo(ownkey) < 0){
            combination = PhageGroupPubKey+ownkey;
        }
        else{
            combination = ownkey+PhageGroupPubKey;
        }
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(combination.getBytes());
        byte[] rendezvousbytes = md.digest();
        String rendezvous = "KSK@" + new String(hex.encode(rendezvousbytes));
        String secretChannelAnnouncement = new String(pcl.getData(rendezvous));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey groupPk = kf.generatePublic(new X509EncodedKeySpec(base64.decode(PhageGroupPubKey)));
        boolean sigValid = c.sigValid(secretChannelAnnouncement.split(":")[0], secretChannelAnnouncement.split(":")[1], groupPk);
        String message = c.decryptMessage(this.getPrivkey(), secretChannelAnnouncement.split(":")[0]);
        System.out.println("SecretChannel: " + message);
        if(!sigValid){
            throw new InvalidSigException("The message signature from " + PhageGroupPubKey + "failed!! Either invalid data was provided or somebody is impersonating this identity.");
        }
        else{
            this.contactChannel=message;
        }

    };

    public PublicKey getPubkey() {
        return pubKey;
    }

    public PrivateKey getPrivkey() {
        return privkey;
    }

    public String getFreenetPubkey() {
        return freenetPubkey;
    }

    public String getFreenetPrivkey() {
        return freenetPrivkey;
    }

    public String getContactChannel() { return contactChannel; }


    @Override
    public String toString(){ Base64 base64 = new Base64(); return base64.encode(this.getPubkey().getEncoded()) + ":" + this.getFreenetPubkey();};


}
