// 
// Decompiled by Procyon v0.5.30
// 

package org.eclipse.jdt.internal.jarinjarloader;

import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public class RsrcURLConnection extends URLConnection
{
    private ClassLoader a;
    
    public RsrcURLConnection(final URL url, final ClassLoader a) {
        super(url);
        this.a = a;
    }
    
    @Override
    public void connect() {
    }
    
    @Override
    public InputStream getInputStream() {
        final InputStream resourceAsStream = this.a.getResourceAsStream(URLDecoder.decode(super.url.getFile(), "UTF-8"));
        if (resourceAsStream == null) {
            throw new MalformedURLException(new StringBuffer("Could not open InputStream for URL '").append(super.url).append("'").toString());
        }
        return resourceAsStream;
    }
}
