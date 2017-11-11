// 
// Decompiled by Procyon v0.5.30
// 

package utils;

import javax.xml.bind.DatatypeConverter;

public class Transformacion
{
    public static String a(final byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }
    
    public static byte[] a(final String s) {
        return DatatypeConverter.parseHexBinary(s);
    }
}
