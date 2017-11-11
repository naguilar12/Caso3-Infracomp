// 
// Decompiled by Procyon v0.5.30
// 

package org.eclipse.jdt.internal.jarinjarloader;

import java.net.URLConnection;
import java.net.URL;
import java.net.URLStreamHandler;

public class RsrcURLStreamHandler extends URLStreamHandler
{
    private ClassLoader a;
    
    public RsrcURLStreamHandler(final ClassLoader a) {
        this.a = a;
    }
    
    @Override
    protected URLConnection openConnection(final URL url) {
        return new RsrcURLConnection(url, this.a);
    }
    
    @Override
    protected void parseURL(final URL url, final String s, final int n, final int n2) {
        String s2;
        if (s.startsWith("rsrc:")) {
            s2 = s.substring(5);
        }
        else if (url.getFile().equals("./")) {
            s2 = s;
        }
        else if (url.getFile().endsWith("/")) {
            s2 = new StringBuffer(String.valueOf(url.getFile())).append(s).toString();
        }
        else {
            s2 = s;
        }
        this.setURL(url, "rsrc", "", -1, null, null, s2, null, null);
    }
}
