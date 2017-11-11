// 
// Decompiled by Procyon v0.5.30
// 

package org.eclipse.jdt.internal.jarinjarloader;

import java.util.ArrayList;
import java.util.jar.Attributes;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.Manifest;
import java.net.URLClassLoader;
import java.net.URLStreamHandlerFactory;
import java.net.URL;

public class JarRsrcLoader
{
    public static void main(final String[] array) {
        final JarRsrcLoader$ManifestInfo a = a();
        URL.setURLStreamHandlerFactory(new RsrcURLStreamHandlerFactory(Thread.currentThread().getContextClassLoader()));
        final URL[] array2 = new URL[a.b.length];
        for (int i = 0; i < a.b.length; ++i) {
            final String s = a.b[i];
            if (s.endsWith("/")) {
                array2[i] = new URL(new StringBuffer("rsrc:").append(s).toString());
            }
            else {
                array2[i] = new URL(new StringBuffer("jar:rsrc:").append(s).append("!/").toString());
            }
        }
        final URLClassLoader contextClassLoader = new URLClassLoader(array2, (ClassLoader)null);
        Thread.currentThread().setContextClassLoader(contextClassLoader);
        Class.forName(a.a, true, contextClassLoader).getMethod("main", array.getClass()).invoke(null, array);
    }
    
    private static JarRsrcLoader$ManifestInfo a() {
        final Enumeration<URL> resources = Thread.currentThread().getContextClassLoader().getResources("META-INF/MANIFEST.MF");
        while (resources.hasMoreElements()) {
            try {
                final InputStream openStream = resources.nextElement().openStream();
                if (openStream == null) {
                    continue;
                }
                final JarRsrcLoader$ManifestInfo jarRsrcLoader$ManifestInfo = new JarRsrcLoader$ManifestInfo(null);
                final Attributes mainAttributes = new Manifest(openStream).getMainAttributes();
                jarRsrcLoader$ManifestInfo.a = mainAttributes.getValue("Rsrc-Main-Class");
                String value = mainAttributes.getValue("Rsrc-Class-Path");
                if (value == null) {
                    value = "";
                }
                jarRsrcLoader$ManifestInfo.b = a(value);
                if (jarRsrcLoader$ManifestInfo.a != null && !jarRsrcLoader$ManifestInfo.a.trim().equals("")) {
                    return jarRsrcLoader$ManifestInfo;
                }
                continue;
            }
            catch (Exception ex) {}
        }
        System.err.println("Missing attributes for JarRsrcLoader in Manifest (Rsrc-Main-Class, Rsrc-Class-Path)");
        return null;
    }
    
    private static String[] a(final String s) {
        if (s == null) {
            return null;
        }
        final ArrayList<String> list = new ArrayList<String>();
        int n;
        for (int i = 0; i < s.length(); i = n + 1) {
            n = s.indexOf(32, i);
            if (n == -1) {
                n = s.length();
            }
            if (n > i) {
                list.add(s.substring(i, n));
            }
        }
        return list.toArray(new String[list.size()]);
    }
}
