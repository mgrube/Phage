/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

import cc.telepath.phage.util.Crypto;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;


import static org.bouncycastle.util.encoders.Base64.encode;


/**
 * This class will define our intitial concept of what a "group" is or looks like.
 * This is the private form of the group - not using FMS or WoT.
 *
 * What should a private Phage group look like?
 *
 * A masterlist maintainted by a single owner or group of "good" identities(public keys)
 * All participants use list of "good" ids to listen/retrieve SSKs for said idents
 * All pariticpants use rotating AES-256 key (default 24 hour rotation)
 * Participants listen to each other. Get info periodically including:
 *  - available samples
 *  - available source files
 *  - available offers(marketplace page template is filled with data fetched)
 *  - general discussion
 *
 * Marketplace Data:
 *
 * Item Name
 * Functionality
 * Price
 * Evidence/Demo
 * Reviews
 *
 * We'll be using the X509 Key Specification.
 *
 *
 * Let's talk about the flow of information for Private forums, since a PhageGroup is a Private Forum.
 *
 * There are two modes of communication: Group and Private.
 *
 * Every participant is subscribed to the same USK(possibly SSK, see which is optimal).
 * The USK provides a list of cryptographic identities+SSK keypairs.
 * The USK has a master public key - when an identity is added to the list, a contact handshake establishing a secret contact point.
 * Should we share a new AES key in the same place or in different secret locations? One place seems to make more sense.
 *
 *
 * PhageGroup Workflow:
 * 1. Group generates and publishes EpochKey
 * 2. Group adds new identities
 * 3. Group announces current key to identities
 * 4. Other identities are updated on newest members.
 *
 *
 */

public class PhageGroup implements Serializable {

    private ArrayList<PhageIdentity> identityList;
    private ArrayList<String> allKeys;
    private PrivateKey PrivateKey;
    private PublicKey PublicKey;
    private String freenetPublicKey;
    private String freenetPrivateKey;
    private String name;
    private HashMap<String, String> privateChannels;
    private ArrayList<String> epochKeys;


    /**
     * Get Group Name
     * @return
     */
    public String getName() {
        return name;
    }


    /**
     * Constructor for building our PhageGroup from a config file.
     * @param publicKey
     * @param privateKey
     * @param freenetPrivateKey
     * @param freenetPublicKey
     * @param name
     */
    public PhageGroup(PublicKey publicKey, PrivateKey privateKey,  String freenetPublicKey,String freenetPrivateKey, String name){
        this.PublicKey = publicKey;
        this.PrivateKey = privateKey;
        this.privateChannels = new HashMap<String, String>();
        this.epochKeys = new ArrayList<String>();
        this.freenetPrivateKey=freenetPrivateKey;
        this.freenetPublicKey=freenetPublicKey;
        this.name=name;
        this.identityList = new ArrayList<PhageIdentity>();

        generateEpochKey();



    }

    public ArrayList<String> getEpochKeys(){
        return  this.epochKeys;
    }

    /**
     * Establish a secure channel with a specific PhageIdentity.
     * The original contact point is determinitstic - take the hash of both keys concatenatd in descending order.
     * Return the secret channel being used to share the current communication AES keys.
     * @param i
     * @return secretchannel
     */
    public String advertiseChannel(PhageIdentity i, PhageFCPClient pcl) throws IOException, FcpException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, SignatureException {
        Base64 base64 = new Base64();
        Hex hex = new Hex();
        String ownkey = new String(base64.encode(this.PublicKey.getEncoded()));
        String identkey = new String(base64.encode(i.getPubkey().getEncoded()));

        String combination = null;
        if(ownkey.compareTo(identkey) < 0){
            combination = ownkey+identkey;
        }
        else{
            combination = identkey+ownkey;
        }

        // Generate a 100 character random KSK for us to meet at
        RandomStringUtils rsu = new RandomStringUtils();
        String channel = rsu.randomAlphanumeric(100);

        Cipher cipher = Cipher.getInstance(i.getPubkey().getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, i.getPubkey());
        String secretchannel = "KSK@" + channel;
        byte[] encryptData = cipher.doFinal(secretchannel.getBytes());

        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initSign(PrivateKey);
        sig.update(new String(base64.encode(encryptData)).getBytes());
        byte[] signatureBytes = sig.sign();
        String encryptedMessage = new String(base64.encode(encryptData));
        String signature = new String(base64.encode(signatureBytes));

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(combination.getBytes());
        byte[] rendezvousbytes = md.digest();

        String rendezvous = new String(hex.encode(rendezvousbytes));
        String URI = pcl.putData(rendezvous, (encryptedMessage+":"+signature).getBytes(),null, null,"text/plain", false);
        this.privateChannels.put(i.getFreenetPubkey(),secretchannel);
        return secretchannel;
    }


    /**
     * Add an identity to the Identity List.
     * @param pi
     */
    public void importIdentity(PhageIdentity pi){
        identityList.add(pi);
    }

    /**
     * Default.
     */
    public PhageGroup(){
        identityList = new ArrayList<PhageIdentity>();
        allKeys = new ArrayList<String>();
        PrivateKey = null;
        PublicKey = null;
        name = "";
        epochKeys = new ArrayList<String>();
    }

    /**
     * When it's time for a new Epoch, add a new key. Announcement comes separately.
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    public void generateEpochKey() {
        Crypto c = new Crypto();
        Base64 base64 = new Base64();
        try {
            String newKey = c.generateAESKey();
            this.epochKeys.add(newKey);
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Takes a base64 encoded 256-bit AES key, announce's on that Identity's private channel
     * @param pi
     * @param AESKey
     */
    public void announceKey(PhageIdentity pi, String AESKey, PhageFCPClient pcl) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException, IOException, FcpException {
        Crypto c = new Crypto();
        String secrectChannel = privateChannels.get(pi.getFreenetPubkey());
        String announcement = "Key:" + AESKey;
        pcl.putData(secrectChannel, c.encryptAndSign(pi.getPubkey(), this.PrivateKey, announcement).getBytes(), null, null, "text/plain", false);
    }

    /**
     * Announce a new AES Key on all private channels.
     */
    public void newEpochAnnouncement(String newKey, PhageFCPClient pcl) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException, IOException, FcpException, NoSuchProviderException {
        Crypto c = new Crypto();
        Base64 base64 = new Base64();
        GsonBuilder b = new GsonBuilder();
        b.disableHtmlEscaping();
        Gson g = b.create();
        for(PhageIdentity pi : identityList){
            EpochAnnouncement announcement = new EpochAnnouncement(newKey, identityList);
            String stringAnnouncement = g.toJson(announcement);
            String AESkey = c.generateAESKey();
            byte[] encryptedAnnouncement = c.AESEncrypt(stringAnnouncement.getBytes(), AESkey);
            //EncrypotAndSign adds a colon to the string so we've been checking the wrong string
            //FIXME
            String encryptedKey = c.encryptAndSign(pi.getPubkey(), this.PrivateKey, AESkey);
            try {
                System.out.println(c.AESDecrypt(base64.decode(new String(base64.encode(encryptedAnnouncement))), AESkey));
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
            System.out.println("Membership announcement on " + pcl.putData(privateChannels.get(pi.getFreenetPubkey()).replace("KSK@", ""), (encryptedKey + ":" + new String(base64.encode(encryptedAnnouncement))).getBytes(), null, null, "text/plain", false));
        }
    }

    public PrivateKey getPrivateKey(){
        return this.PrivateKey;
    }

    public PublicKey getPublicKey(){
        return this.PublicKey;
    }

    /**
     * Use the most recent epoch key to encrypt and publish a full list of member public keys and Freenet publickeys
     * @param pcl
     */
    public void membershipAnnouncement(PhageFCPClient pcl){
        Crypto c = new Crypto();
        Base64 base64 = new Base64();
        String membershipList = "";
        for(PhageIdentity i : this.identityList){
            membershipList += i + "\n";
        }
        String encryptedList = new String(base64.encode(c.AESEncrypt(membershipList.getBytes(), this.epochKeys.get(epochKeys.size()-1))));
        System.out.println("Announcement on: " + pcl.putData(null, encryptedList.getBytes(), this.freenetPrivateKey, "memberList", "text/plain", true));

    }

    /**
     * Takes a base64 encoded string
     * @param privateKey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void setPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Base64 base64 = new Base64();
        this.PrivateKey = KeyFactory.getInstance("RSA", "BC").generatePrivate(new X509EncodedKeySpec(base64.decode(privateKey)));
    }

    /**
     * Takes a base64 encoded string
     * @param publicKey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void setPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Base64 base64 = new Base64();
        this.PublicKey = KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(base64.decode(publicKey)));
    }

    /**
     * Take a Base64 representation of a key
     * @param pubKey
     * @throws IOException, InvalidKeyException
     */
    public void importIdentity(String pubKey, String FreenetURI) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        identityList.add(new PhageIdentity(pubKey, FreenetURI));
    }

    /**
     * Gets the Freenet Public Key for the group
     * @return
     */
    public String getFreenetPublicKey(){
        return this.freenetPublicKey;
    }


    @Override
    public String toString(){
        return "Dongs";
    }

}