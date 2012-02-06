/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.logiclander.jaasminetest.ws;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.ws.rs.core.EntityTag;

/**
 *
 * @author agherna
 */
public class EntityTagGenerator {

    private static final byte[] HEX_CHAR_TABLE = {
        (byte) '0', (byte) '1', (byte) '2', (byte) '3',
        (byte) '4', (byte) '5', (byte) '6', (byte) '7',
        (byte) '8', (byte) '9', (byte) 'a', (byte) 'b',
        (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'
    };


    private EntityTagGenerator() {
        // empty constructor.
    }


    public static EntityTag generate(String seed)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {

        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(seed.getBytes());

        return new EntityTag(getHexString(md.digest()));
    }

    public static String getHexString(byte[] raw)
            throws UnsupportedEncodingException {
        byte[] hex = new byte[2 * raw.length];
        int index = 0;

        for (byte b : raw) {
            int v = b & 0xFF;
            hex[index++] = HEX_CHAR_TABLE[v >>> 4];
            hex[index++] = HEX_CHAR_TABLE[v & 0xF];
        }
        return new String(hex, "ASCII");
    }
}
