package cc.telepath.phage;

import com.google.gson.Gson;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;

public class Configuration {

    private String filepath;

    public Configuration(String configfile, String password){
        try {
            Gson gson = new Gson();
            FileInputStream fis = new FileInputStream(new File(configfile));


        }
        catch (FileNotFoundException e){
            File config = new File(configfile);
        }


    }

    public void writeConfig(){

    }

    public void readConfig(String filepath){

    }

}
