/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

import java.io.*;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import cc.telepath.phage.util.Crypto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import net.pterodactylus.fcp.highlevel.FcpException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;

import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.test.FixedSecureRandom;
import spark.ModelAndView;
import spark.template.velocity.VelocityTemplateEngine;
import org.apache.commons.lang.RandomStringUtils;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


import static spark.Spark.*;

public class Phage {



    private ArrayList<PhageGroup> communities;

    public Phage(){
        this.communities = new ArrayList<PhageGroup>();
    }


    /**
     * Write config file.
     * Must be encrypted with password.
     * @param configFile
     * @param password
     */
    public void writeConfig(String configFile, String password){
        try {
            Base64 base64 = new Base64();
            Crypto c = new Crypto();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(this.communities);
            String key = c.passwordToAESKey(password);
            byte[] encryptedObj = c.AESEncrypt(bos.toByteArray(), key);
            BufferedWriter bw = new BufferedWriter(new FileWriter(configFile));
            bw.write(new String(base64.encode(encryptedObj)));
            bw.close();
            oos.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Read config file.
     * Must be decrypted with password.
     * This is insanely unsafe but will at least make it harder to recovery sensitive info.
     * TODO: Convert to JSON
     * @param configFile
     * @param password
     */
    public void readConfig(String configFile, String password) throws FileNotFoundException{
        try {
            Crypto c = new Crypto();
            Base64 base64 = new Base64();
            BufferedReader br = new BufferedReader(new FileReader(configFile));
            String encryptedConfig = br.readLine();
            String key = c.passwordToAESKey(password);
            byte[] encryptedObj = c.AESDecrypt(base64.decode(encryptedConfig), key);
            ByteArrayInputStream bis = new ByteArrayInputStream(encryptedObj);
            ObjectInputStream ois = new ObjectInputStream(bis);
            ArrayList<PhageGroup> communities = (ArrayList<PhageGroup>) ois.readObject();
            System.out.println(communities);
            this.communities = communities;
        }
        catch (BadPaddingException e){
            System.out.println("Incorrect AES Key when decrypting config file.");
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }



    public static void main(String args[]) throws IOException, FcpException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidSigException, InvalidAlgorithmParameterException {
        final PhageFCPClient pcl = new PhageFCPClient();
        pcl.connect("127.0.0.1");
        Phage p = new Phage();
        Crypto c = new Crypto();
        Base64 base64 = new Base64();
        String encryptedText = new String(base64.encode(c.AESEncrypt("This is a test AES Encrypted message.".getBytes(), c.passwordToAESKey("Dongs"))));
        System.out.println(new String(c.AESDecrypt(base64.decode(encryptedText), c.passwordToAESKey("Dongs"))));
        boolean passphraseProvided = false;
        HashMap<String, String> keys = pcl.generateKeypair();
        KeyPair k = c.generateKeypair();
        PhageIdentity a = new PhageIdentity(k.getPublic(), k.getPrivate(), keys.get("public"), keys.get("private"));
        keys = pcl.generateKeypair();
        k = c.generateKeypair();
        PhageIdentity b = new PhageIdentity(k.getPublic(), k.getPrivate(), keys.get("public"), keys.get("private"));
        keys = pcl.generateKeypair();
        k = c.generateKeypair();
        PhageIdentity d = new PhageIdentity(k.getPublic(), k.getPrivate(), keys.get("public"), keys.get("private"));
        keys = pcl.generateKeypair();
        k = c.generateKeypair();
        PhageIdentity e = new PhageIdentity(k.getPublic(), k.getPrivate(), keys.get("public"), keys.get("private"));
        k = c.generateKeypair();
        keys = pcl.generateKeypair();
        PhageGroup pg = new PhageGroup(k.getPublic(), k.getPrivate(), keys.get("public"), keys.get("private"), "TestGroup");
        pg.generateEpochKey();
        pg.importIdentity(a);
        pg.importIdentity(b);
//        pg.importIdentity(d);
//        pg.importIdentity(e);
        pg.membershipAnnouncement(pcl);
        pg.advertiseChannel(a, pcl);
        pg.advertiseChannel(b, pcl);
//        pg.advertiseChannel(d, pcl);
//        pg.advertiseChannel(e, pcl);
        a.discoverSecretChannel(new String(base64.encode(pg.getPublicKey().getEncoded())),pcl);
        b.discoverSecretChannel(new String(base64.encode(pg.getPublicKey().getEncoded())),pcl);
//        d.discoverSecretChannel(new String(base64.encode(pg.getPublicKey().getEncoded())),pcl);
//        e.discoverSecretChannel(new String(base64.encode(pg.getPublicKey().getEncoded())),pcl);
        pg.newEpochAnnouncement(pg.getEpochKeys().get(pg.getEpochKeys().size()-1), pcl);



        final String URI = pg.getFreenetPublicKey().replace("SSK@","USK@") + "0";
        Thread t = new Thread(){
            public void run() {
                try {
                    pcl.subscribeUSK(URI);
                }
                catch (IOException e){
                    e.printStackTrace();
                }
                catch (FcpException e){
                    e.printStackTrace();
                }
            }

        };
        t.start();
        //pg.membershipAnnouncement(pcl);
        byte[] memberlistbytes = pcl.getData(a.getContactChannel());
        String memberlist = new String(memberlistbytes);
        System.out.println("Recovered key: " + c.decryptMessage(a.getPrivkey(),memberlist.split(":")[0]));
        String recoveredKey = c.decryptMessage(a.getPrivkey(),memberlist.split(":")[0]);
        System.out.println("MEMBERLIST DATA: " + memberlist);
//        System.out.println("Second half:" + memberlist.split(":")[1]);
//        String AESDecryptedMessage = c.AESDecrypt()
        System.out.println(new String(c.AESDecrypt(base64.decode(memberlist.split(":")[2]),  c.decryptMessage(a.getPrivkey(),memberlist.split(":")[0]))));
        //System.out.println("Recovered message:" + new String(c.AESDecrypt(base64.decode(memberlist.split(":")[1]),recoveredKey)));
        //pcl.putData(null, "This is some more test data".getBytes(), keys.get("private"), "messages", "text/plain", true);
        pcl.close();
        System.exit(0);


//
//        port(8890);
//        staticFiles.location("/public");
//
//        get("/create", (req, res) -> {
//            return null;
//        });
//
//        get("/config", (req, res) -> {return null;});
//
//        post("/create", (req, res) -> {
//            System.out.println(req.queryParams("communityname"));
//            return req.queryParams("communityname");
//        });
//
//        get("/", (req, res) -> {
//            Map<Object, String> model = new HashMap<>();
//            model.put("passphraseProvided", passphraseProvided);
//            return new ModelAndView(new HashMap<>(), "main.vm");
//        }, new VelocityTemplateEngine());
//
//        get("/hello", (req, res) -> {
//            Map<String, Object> model = new HashMap<>();
//            model.put("message", "Fuck the police!");
//
//            // The vm files are located under the resources directory
//            return new ModelAndView(model, "hello.vm");
//        }, new VelocityTemplateEngine());
//
//        get("/shutdown", (req, res) -> {
//            stop();
//            System.exit(0);
//            return null;
//        });

    }

}