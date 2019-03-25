/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

import net.pterodactylus.fcp.*;
import net.pterodactylus.fcp.highlevel.*;

import java.io.*;
import java.lang.reflect.Array;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Stack;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import net.pterodactylus.fcp.highlevel.FcpException;
import org.apache.commons.io.IOUtils;

import java.util.Scanner;


public class PhageFCPClient implements Closeable   {

    private String hostname;
    private int connectionport;
    private NodeHello nodeHello;
    private FcpConnection fcpConnection;
    private boolean connected;
    private final Object syncObject = new Object();
    private String finaluri;

    public boolean getConnected(){
        return connected;
    }

    public NodeHello getNodeHello(){
        return nodeHello;
    }


    /**
     * Returns a hashmap of public and private keys for publishing data.
     * To get the public key, get the "public" key of the map.
     * To get the private key, get "private".
     * @return
     * @throws IOException
     * @throws FcpException
     */
    public HashMap<String, String> generateKeypair() throws IOException, FcpException{
        final HashMap<String, String> keys = new HashMap<String, String>();
        new ExtendedAdapter(){

            @Override
            public void run() throws IOException {
                GenerateSSK req = new GenerateSSK();
                fcpConnection.sendMessage(req);
            }

            @Override
            public void receivedSSKKeypair(FcpConnection fcpConnection, SSKKeypair sskKeypair){
                keys.put("private", sskKeypair.getInsertURI());
                keys.put("public", sskKeypair.getRequestURI());
                completionLatch.countDown();
            }
        }.execute();
        return keys;
    }


    /**
     * See if a USK is updated.
     * @param URI
     * @param identifier
     * @throws IOException
     * @throws FcpException
     */
    public void subscribeUSK(final String URI) throws IOException, FcpException {
        new ExtendedAdapter(){

            final String identifier = nodeHello.getConnectionIdentifier();
            @Override
            public void run() throws IOException {
                SubscribeUSK susk = new SubscribeUSK(URI, identifier);
                fcpConnection.sendMessage(susk);

            }

            @Override
            public void receivedSubscribedUSK(FcpConnection fcpConnection, SubscribedUSK subscribedUSK){
                if(subscribedUSK.getIdentifier().equals(identifier)) {
                    System.out.println("Successfully subscribed");
                }
            }

            @Override
            public void receivedSubscribedUSKUpdate(FcpConnection fcpConnection, SubscribedUSKUpdate subscribedUSKUpdate){
                if(subscribedUSKUpdate.getIdentifier().equals(identifier)) {
                    System.out.println("Received USK update: " + subscribedUSKUpdate.getURI());
                }
            }


        }.execute();
    }

    /**
     * TODO: Turn this into a DDAHandshake function where read and write can be specified through arguments. Handle errors better.
     * If we haven't established DDA for a specific directory, do that.
     * @param directory - The directory you want to establish Direct-Disk Access for.
     *
     * @return
     * @throws IOException
     * @throws FcpException
     */
    public void DDAReadHandshake(final String directory) throws IOException, FcpException{

        new ExtendedAdapter(){

            @Override
            public void run() throws IOException{
                TestDDARequest tr = new TestDDARequest(new File(directory).getPath(), true, false);
                fcpConnection.sendMessage(tr);
            }

            @Override
            public void receivedProtocolError(FcpConnection fcpConnection, ProtocolError protocolError){
                System.out.println(protocolError.getCodeDescription());
                System.out.println(protocolError.getCode());
                System.out.println(protocolError.getExtraDescription());
            }

            @Override
            public void receivedTestDDAReply(FcpConnection fcpConnection, TestDDAReply testDDAReply){
                try {
                    BufferedReader br = new BufferedReader(new FileReader((testDDAReply.getReadFilename())));
                    String line = br.readLine();
                    br.close();
                    TestDDAResponse TDR = new TestDDAResponse(testDDAReply.getDirectory(), line);
                    fcpConnection.sendMessage(TDR);
                }
                catch (Exception e){
                    e.printStackTrace();
                }
            }

            @Override
            public void receivedTestDDAComplete(FcpConnection fcpConnection, TestDDAComplete testDDAComplete){
                //If the Complete is for our directory of interest...
                if(testDDAComplete.getDirectory().equals(new File(directory).getPath())){
                    completionLatch.countDown();
                }
            }
        }.execute();


    }

    /**
     * Insert a directory of data. Useful for USKs/site inserts.
     * The insert is recursive.
     * @param dirpath
     * @param
     */
    public void putDir(final String dirpath, final String sitename, final String privateKey, final String defaultFile, final boolean USK) throws IOException, FcpException{

        new ExtendedAdapter(){
            public void run() throws IOException {
                ClientPutComplexDir pdir;
                if(USK){
                    String newuri = privateKey.replace("SSK@", "USK@");
                    pdir = new ClientPutComplexDir(sitename, newuri + sitename + "/0");
                }
                else {
                    pdir = new ClientPutComplexDir(sitename, privateKey + sitename);
                }
                if(defaultFile != null){
                    pdir.setDefaultName(defaultFile);
                }
                File folder = new File(dirpath);
                for(File f: folder.listFiles()){
                    pdir.addFileEntry(FileEntry.createDiskFileEntry(f.getName(),f.getAbsolutePath(),null,-1));
                }
                pdir.setPersistence(Persistence.forever);
                pdir.setGlobal(true);
                fcpConnection.sendMessage(pdir);
            }

            @Override
            public void receivedProtocolError(FcpConnection fcpConnection, ProtocolError protocolError){
                System.out.println(protocolError.getFields());
            }

            @Override
            public void receivedPersistentPutDir(FcpConnection fcpConnection, PersistentPutDir persistentPutDir){
                System.out.println(persistentPutDir.getFields());
                completionLatch.countDown();
            }
        }.execute();

    }


    /**
     * Function for easy CHKing of raw data
     * @param data
     */
    public String putData(byte[] data) throws IOException, FcpException {

        return putData(null, data, null, null, null, false);

    }

    /**
     * Put some raw data directly into Freenet
     */
    public String putData(final String KSKName, byte[] data, final String privateKey, final String filename, final String mimetype, final boolean USK) {

        final byte[] ndata = data;
        final StringBuilder finalURI = new StringBuilder();
        Random rand = new Random();
        try {
            final String identifier = nodeHello.getConnectionIdentifier() + rand.nextDouble();

            new ExtendedAdapter() {

                @Override
                public void run() {

                    try {
                        String uri = "";
                        UploadFrom fromDirect = UploadFrom.direct;

                        if (privateKey != null && privateKey != "" && USK) {
                            uri = privateKey.replace("SSK@", "USK@") + filename + "/0";
                        } else if (privateKey != null && privateKey != "") {
                            uri = privateKey + filename;

                        } else if (KSKName != null && KSKName != "") {
                            uri = "KSK@" + KSKName;
                        } else {
                            uri = "CHK@";
                        }
                        ClientPut cp = new ClientPut(uri, identifier, fromDirect);
                        if (filename != null && filename != "") {
                            cp.setFilename(filename);
                        }
                        if (mimetype != null) {
                            cp.setMetadataContentType(mimetype);
                        }
                        if (USK) {
                            cp.setPriority(Priority.maximum);
                            cp.setField("RealTimeFlag", "true");

                        }
                        cp.setDataLength(ndata.length);
                        cp.setPayloadInputStream(new ByteArrayInputStream(ndata));
                        cp.setPersistence(Persistence.forever);
                        cp.setGlobal(false);

                        fcpConnection.sendMessage(cp);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                /**
                 * We know our Put was successfully started when we receive the ExpectedHashes message from the node.
                 *
                 * @param fcpConnection
                 * @param fcpMessage
                 */
                @Override
                public void receivedPutSuccessful(FcpConnection fcpConnection, PutSuccessful putSuccessful) {
                    if (putSuccessful.getIdentifier().equals(identifier)) {
                        finalURI.append(putSuccessful.getURI());
                        completionLatch.countDown();
                    }

                }

                @Override
                public void receivedProtocolError(FcpConnection fcpConnection, ProtocolError protocolError) {

                    System.out.println(protocolError.getFields());
                    completionLatch.countDown();

                }

                @Override
                public void receivedMessage(FcpConnection fcpConnection, FcpMessage fcpMessage) {
                    //System.out.println(fcpMessage.getFields());

                }


            }.execute();
        }
        catch (Exception e){
            e.printStackTrace();;
        }

        return finalURI.toString();
    }

    /**
     * This should really read bytes, not characters. Stupid approach. Change this.
     * Get some data over FCP as a string.
     * @param URI
     * @throws IOException
     * @throws FcpException
     */
    public byte[] getData(final String URI) throws IOException, FcpException, IOException{

        final Stack<byte[]> dataBytes = new Stack<byte[]>();

        new ExtendedAdapter(){
            @Override
            public void run() throws IOException {
                ClientGet cg = new ClientGet(URI, nodeHello.getConnectionIdentifier());
                fcpConnection.sendMessage(cg);
            }
            

            @Override
            public void receivedProtocolError(FcpConnection fcpConnection, ProtocolError protocolError){
                System.out.println(protocolError.getFields());
            }

            @Override
            public void receivedPersistentGet(FcpConnection fcpConnection, PersistentGet persistentGet){
                System.out.println(persistentGet.getFields());
            }

            @Override
            public void receivedAllData(FcpConnection fcpConnection, AllData allData){
                String output;
                InputStream is = allData.getPayloadInputStream();

                try {
                    byte[] bytes = IOUtils.toByteArray(is);
                    dataBytes.push(bytes);
                }
                catch(IOException e){
                    e.printStackTrace();
                }
                completionLatch.countDown();

            }

        }.execute();


        return dataBytes.pop();
    }


    /**
     * Simple form of putFile.
     * Assumes the user wants a CHK.
     * @param filepath
     */
    public void putFile(final String filepath) throws IOException, FcpException{
        putFile(filepath, null);

    }

    //public void directUSK(String privateKey, )

    /**
     * Let's write our own put
     * With blackjack and hookers!
     * Writing this in test mode because I'm still working on this stuff.
     *
     * @param filepath - The full path of the file being inserted.
     *
     * @return
     */
    public void putFile(final String filepath, final String privatekey) throws IOException, FcpException{

        new ExtendedAdapter(){
            final String identifier = nodeHello.getConnectionIdentifier();

            @Override
            public void run() {

                UploadFrom fromdisk = UploadFrom.disk;
                String uri = "CHK@";
                if(privatekey != null){
                    uri = privatekey + filepath.split("/")[filepath.split("/").length - 1];
                }
                ClientPut cp = new ClientPut(uri, identifier, fromdisk);
                cp.setFilename(filepath);
                cp.setPersistence(Persistence.forever);
                cp.setGlobal(true);
                cp.setTargetFilename(filepath.split("/")[filepath.split("/").length - 1]);
                try {
                    fcpConnection.sendMessage(cp);
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }

            /**
             * Stop the thread when we receive PutSuccessful.
             * @param fcpConnection
             * @param putSuccessful
             */
            @Override
            public void receivedPutSuccessful(FcpConnection fcpConnection, PutSuccessful putSuccessful){
                if(putSuccessful.getIdentifier().equals(identifier)){
                    completionLatch.countDown();
                }
            }

            @Override
            public void receivedProtocolError(FcpConnection fcpConnection, ProtocolError protocolError){
                if(protocolError.getIdentifier().equals(identifier)){
                    System.out.println("FCP Error received for file " + filepath);
                    System.out.println("Code: " + protocolError.getCode());
                    System.out.println("Description: " + protocolError.getCodeDescription());
                    System.out.println("Extra Description: " + protocolError.getExtraDescription());
                    completionLatch.countDown();
                }
            }



        }.execute();
    }

    public void connect(final String name) throws IOException, FcpException {
        checkConnected(false);
        connected = true;
        new ExtendedAdapter() {

            /**
             * {@inheritDoc}
             */
            @Override
            @SuppressWarnings("synthetic-access")
            public void run() throws IOException {
                fcpConnection.connect();
                ClientHello clientHello = new ClientHello(name);
                fcpConnection.sendMessage(clientHello);
                WatchGlobal watchGlobal = new WatchGlobal(true);
                fcpConnection.sendMessage(watchGlobal);
                //fcpConnection.sendMessage();

            }

            /**
             * {@inheritDoc}
             */
            @Override
            @SuppressWarnings("synthetic-access")
            public void receivedNodeHello(FcpConnection fcpConnection, NodeHello nodeHello) {
                PhageFCPClient.this.nodeHello = nodeHello;
                completionLatch.countDown();
            }
        }.execute();
    }


    public void disconnect() {
        synchronized (syncObject) {
            fcpConnection.close();
            syncObject.notifyAll();
        }
    }

    public void close(){
        disconnect();
    }

    private abstract class ExtendedAdapter extends FcpAdapter{

        protected final CountDownLatch completionLatch = new CountDownLatch(1);

        protected Request recvrec;

        protected FcpException fcpException;


        /**
         * Blank constructor
         */
        public ExtendedAdapter(){

        }

        @SuppressWarnings("synthetic-access")
        public void execute() throws IOException, FcpException {
            checkConnected(true);
            fcpConnection.addFcpListener(this);
            try {
                run();
                while (true) {
                    try {
                        completionLatch.await();
                        break;
                    } catch (InterruptedException ie1) {
						/* ignore, we’ll loop. */
                    }
                }
            } catch (IOException ioe1) {
                setDisconnected();
                throw ioe1;
            } finally {
                fcpConnection.removeFcpListener(this);
            }
            if (fcpException != null) {
                setDisconnected();
                throw fcpException;
            }
        }




        public abstract void run() throws IOException;


        }


    // Set disconnected.
    private void setDisconnected(){
        this.connected = false;
    }


    private void checkConnected(boolean connected) throws FcpException {
        if (this.connected != connected) {
            throw new FcpException("Client is " + (connected ? "not" : "already") + " connected.");
        }
    }

    public PhageFCPClient(String hostname, int port) throws UnknownHostException{
        this.hostname = hostname;
        this.connectionport = port;
        fcpConnection = new FcpConnection(hostname, port);
    }

    public PhageFCPClient() throws UnknownHostException {
        this("127.0.0.1", 9481);
    }



}
