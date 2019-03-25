/**
 * Copyright 2018 (c) Michael Grube
 *
 * This code is distributed under the GNU GPL Version 3.
 * For details, please read the LICENSE file.
 *
 */

package cc.telepath.phage;

public class InvalidSigException extends Exception {

    public InvalidSigException(){

    }

    public InvalidSigException(String message){
        super(message);
    }

    public InvalidSigException(Throwable cause){
        super(cause);
    }

}
