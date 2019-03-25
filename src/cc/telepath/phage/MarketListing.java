/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;


/**
 * you have: image library which is a set of URIs of images, a title, a decsciption, a price and a currency
 */
public class MarketListing {

    public enum CURRENCY{
        MONERO,
        BITCOIN,
        ETHEREUM,
        DOLLARS

    }

    private ArrayList<String> Pictures;
    private String Title;
    private String Description;
    private double price;
    private CURRENCY currency;

    public RSAPublicKey getAuthorKey() {
        return authorKey;
    }

    private RSAPublicKey authorKey;


    public MarketListing(String Title, String Description, double price, CURRENCY currency){
        Pictures = new ArrayList<String>();
        this.Title = Title;
        this.Description = Description;
        this.price = price;
        this.currency = currency;

    }

    public void addPicture(String URI){
        Pictures.add(URI);
    }

    public CURRENCY getCurrency() { return currency; }

    public ArrayList<String> getPictures() {
        return Pictures;
    }

    public String getTitle() {
        return Title;
    }

    public String getDescription() {
        return Description;
    }

    public double getPrice() {
        return price;
    }


}
