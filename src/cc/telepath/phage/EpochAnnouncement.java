package cc.telepath.phage;

import org.bouncycastle.util.encoders.Base64;

import java.util.ArrayList;
import java.util.HashMap;

public class EpochAnnouncement {

    private String key;

    private HashMap<String, String> members;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public HashMap<String, String> getMembers() {
        return members;
    }

    public void setMembers(HashMap<String, String> members) {
        this.members = members;
    }

    public EpochAnnouncement(String key, ArrayList<PhageIdentity> memberList){

        this.key = key;
        this.members = new HashMap<String, String>();
        Base64 base64 = new Base64();

        for(PhageIdentity i : memberList){
            members.put(i.getFreenetPubkey(), new String(base64.encode(i.getPubkey().getEncoded())));
        }


    }

}
