// 
// Decompiled by Procyon v0.5.30
// 

package org.eclipse.jdt.internal.jarinjarloader;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

public class RsrcURLStreamHandlerFactory implements URLStreamHandlerFactory
{
    private ClassLoader a;
    private URLStreamHandlerFactory b;
    
    public RsrcURLStreamHandlerFactory(final ClassLoader a) {
        this.a = a;
    }
    
    @Override
    public URLStreamHandler createURLStreamHandler(final String s) {
        if ("rsrc".equals(s)) {
            return new RsrcURLStreamHandler(this.a);
        }
        if (this.b != null) {
            return this.b.createURLStreamHandler(s);
        }
        return null;
    }
}
