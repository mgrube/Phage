/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

import java.io.*;
import net.pterodactylus.fcp.*;

import java.net.UnknownHostException;
import java.util.ArrayList;
import net.pterodactylus.fcp.highlevel.FcpClient;
import net.pterodactylus.fcp.highlevel.PutRequest;
import cc.telepath.phage.Sample.exectype;


/**
 *  Manages Samples and inserts, if necessary
 */

class SampleManager{

    private String publickey;
    private String privatekey;
    private String sampledirectory;
    private Peer p;
    private ArrayList<String> directories;


    /**
     * Searches our directory for executables. For each executable, add a Sample object to the samples list.
     * Another method stolen straight off of StackOverflow!
     * @return
     */
    private ArrayList<Sample> loadDirectory(String samplepath){

        File directory = new File(samplepath);
        File[] listOfFiles = directory.listFiles();
        ArrayList<Sample> samples = new ArrayList<Sample>();

        for (int i = 0; i < listOfFiles.length; i++){
            if (listOfFiles[i].isFile()) {
                if ((new Sample(listOfFiles[i].getAbsolutePath())).getFormat() != exectype.OTHER){ //This is dirty and stupid.
                    samples.add(new Sample(listOfFiles[i].getAbsolutePath()));
                }
            }
        }

        return samples;

    }

    // In our list of samples, insert!
    private boolean insertSample(Sample s) throws UnknownHostException{
        //ClientPut cp = new ClientPut();
        return false;
    }

    public SampleManager(){

    }

    public SampleManager(String PublicKey, String PrivateKey){
        this.publickey=PublicKey;
        this.privatekey=PrivateKey;
    }


    public static void main(String args[]) {
        SampleManager sm = new SampleManager();

    }

}