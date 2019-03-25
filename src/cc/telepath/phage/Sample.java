/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.DigestInputStream;

/**
 * Class to define a Malware Sample
 */
public class Sample {

    public enum exectype {
        PE, ELF, MACHO, CLASS, OTHER
    }

    private String path;

    private String sha256sum;

    private exectype format;

    private long filesize;

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public exectype getFormat(){
        return this.format;
    }

    public String getSha256sum(){
        return this.sha256sum;
    }

    public String getPath(){
        return path;
    }

    public long getFilesize(){
        return this.filesize;
    }

    /**
     * Pass a path and have the rest determined for us.
     * @param path
     */
    public Sample(String path) {
        this.path=path;
        File samplefile = new File(path);
        this.format = executableType(samplefile);
        this.sha256sum = SHA256HashDigest(samplefile);
        this.filesize = samplefile.length();
    }

    /**
     * Take a file and read the magic number to determine what kind of executable it is.
     * @param file
     * @return An Enum
     */
    private exectype executableType(File file) {
        byte[] firstBytes = new byte[4];
        exectype ret = exectype.OTHER;
        try {
            FileInputStream input = new FileInputStream(file);
            input.read(firstBytes);

            // Check for PE executable
            if (firstBytes[0] == 0x4d && firstBytes[1] == 0x5a) {
                ret =  exectype.PE;
            }
            // Check for ELF executable
            if (firstBytes[0] == 0x7f && firstBytes[1] == 0x45 && firstBytes[2] == 0x4c && firstBytes[3] == 0x46){
                ret = exectype.ELF;
            }
            // Check for Java Class
            if (firstBytes[0] == 0xca && firstBytes[0] == 0xfe && firstBytes[0] == 0xba && firstBytes[0] == 0xbe){
                ret = exectype.CLASS;
            }
            // Check for Mach-O
            if (firstBytes[0] == 0xfe && firstBytes[0] == 0xed && firstBytes[0] == 0xfa && firstBytes[0] == 0xce){
                ret = exectype.MACHO;
            }

        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }


    /**
     * Return a Hex string that represents the SHA256 digest of the file.
     * Takes a file
     * @param f - The file we want the sha256sum for.
     * @return
     */
    private String SHA256HashDigest(File f){

        byte[] digest = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(f);
            DigestInputStream dis = new DigestInputStream(fis, md);
            byte[] data = new byte[(int) f.length()];
            dis.read(data, 0, (int) f.length());
            digest = md.digest();
        }
        catch (IOException e){
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }

        return bytesToHex(digest);
    }

    /**
     * I stole this straight off of StackOverflow.
     * Takes an array of bytes and returns a hex string.
     * @param bytes
     * @return
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


}
