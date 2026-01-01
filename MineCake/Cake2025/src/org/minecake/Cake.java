package org.minecake;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.security.Key;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Cake extends ClassLoader {
    private ByteArrayInputStream[] k;
    private int[] m;
    private int[] i;
    private byte[][] l;
    private byte[][] h;
    private int[] f;
    private Map<String, Integer> C;
    private Map<String, Integer> a;
    private byte[][] CAKE;

    public static void begin(Object[] a) {
        String string;
        String string2;
        String[] stringArray;
        boolean bl;
        try {
            bl = (Boolean) a[0];
            stringArray = (String[]) a[1];
            string2 = (String) a[2];
            string = (String) a[3];
        } catch (Exception exception) {
            return;
        }
        try {
            if (!(stringArray != null && bl && string2 != null && string != null && string2.equals(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u000e\u0013.'zI\u0013\u0016>(+\t>\";\u0014 \u001a'?\u007f o@\"/\n\u0016(9\u00180"))) && string.equals(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u00188\f|\u001e%7C\t)933p\u001b~"))))) {
                return;
            }
            if (stringArray.length >= 3) {
                if (stringArray[0] != null) {
                    if (stringArray[1] != null) {
                        if (stringArray[2] != null) {
                            if (stringArray[0].equals(Deobfuscator.decodeWithContext(Deobfuscator.getString("+\ry\u007f~*$\u0003\u0001\u0000\u000be(c_$wz`|/(")))) {
                                if (stringArray[2].length() == 32) {
                                    Cake cake = new Cake(bl, stringArray, string2, string);
                                    Class<?> clazz = cake.findClass(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0002)&#")));
                                    if (clazz != null) {
                                        StringBuilder sb = new StringBuilder();
                                        for (int i = stringArray[2].length() - 1; i >= 0; i--) {
                                            char c = stringArray[2].charAt(i);
                                            switch (c) {
                                                case 'g': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("r"))); break;
                                                case '4': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("!"))); break;
                                                case 'T': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0007"))); break;
                                                case 'A': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0012"))); break;
                                                case 'R': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("7"))); break;
                                                case 'q': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0014"))); break;
                                                case 'x': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("\n"))); break;
                                                case 'L': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString(">"))); break;
                                                case '6': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("$"))); break;
                                                case 'b': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("p"))); break;
                                                case '3': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("%"))); break;
                                                case 'c': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("u"))); break;
                                                case 'B': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("~"))); break;
                                                case '8': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0004"))); break;
                                                case 'v': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("1"))); break;
                                                case 'w': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("0"))); break;
                                                case 'P': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0013"))); break;
                                                case 'U': sb.append(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0016"))); break;
                                                default: sb.append(c); break;
                                            }
                                        }
                                        stringArray[2] = sb.toString();
                                        stringArray[0] = Deobfuscator.decodeWithContext(Deobfuscator.getString("\"\u00116l\u000b\u0004'\u0005\tg|*\u001d(\u0004\u001bq%=hfc\u0017%$rmr/&5\u0000\n\r\u0019(\u0004 <<7'b|#=\u0007"));
                                        Class<?>[] classArray = new Class[1];
                                        classArray[0] = String[].class;
                                        Object[] objectArray = new Object[1];
                                        objectArray[0] = stringArray;
                                        clazz.getMethod(Deobfuscator.decodeWithContext(Deobfuscator.getString("()\"(")), classArray).invoke(null, objectArray);
                                        return;
                                    }
                                    clazz = cake.findClass("org.minecake.Cake");
                                    if (clazz != null) {
                                        Class<?>[] classArray = new Class[1];
                                        classArray[0] = Object[].class;
                                        Object[] objectArray = new Object[1];
                                        objectArray[0] = a;
                                        clazz.getMethod(Deobfuscator.decodeWithContext(Deobfuscator.getString("  /\"(")), classArray).invoke(null, objectArray);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception exception) {
            // empty catch block
        }
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            // Check if we are responsible for loading this class
            if (!this.a.containsKey(name)) {
                return super.findClass(name);
            }
            int classIndex = this.a.get(name);
            if (classIndex < 0) {
                return null;
            }

            // This seems to be a placeholder for some logic, but it's not clear what it does.
            if (classIndex == -32 || classIndex == -128 || classIndex == -256 || classIndex == -512 || classIndex == -1024) {
                byte[] object = Deobfuscator.decodeWithContext(Deobfuscator.getString("3\u0007\u0003hz~p")).getBytes();
                this.defineClass(null, object, 0, object.length);
            }

            // Extract IV from the h table
            byte[] iv = new byte[16];
            for (int j = 0; j < 16; j++) {
                iv[j] = this.h[this.m[classIndex]][this.f[classIndex] + j];
            }

            // More placeholder logic for specific IV lengths
            if (iv.length == 128 || iv.length == 2048) {
                byte[] byArray = Deobfuscator.decodeWithContext(Deobfuscator.getString("\n\u0003\u001eo\f\u0000\u0006g\u001b\rC^X0\u000e\u0006\u0001\u0001\u0005\u0001")).getBytes();
                this.defineClass(null, byArray, 0, byArray.length);
                for (int j = 0; j < byArray.length; ++j) {
                    this.defineClass(null, byArray, 0, byArray.length);
                    this.defineClass(null, byArray, 0, byArray.length);
                    this.defineClass(null, byArray, 0, byArray.length);
                }
            }

            // Extract encrypted class bytes
            byte[] classBytes = new byte[this.i[classIndex]];
            for (int j = 0; j < this.i[classIndex]; ++j) {
                classBytes[j] = this.h[this.m[classIndex]][this.f[classIndex] + 16 + j];
            }

            // Verify hash of the class bytes
            MessageDigest messageDigest = MessageDigest.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("3\u0007\u0003hz~p")));
            messageDigest.reset();
            messageDigest.update(classBytes);
            byte[] hash = messageDigest.digest();
            for (int j = 0; j < this.l[classIndex].length; ++j) {
                if (this.l[classIndex][j] != hash[j]) {
                    return null;
                }
            }

            // Decrypt and define the class
            Class<?> clazz = null;
            byte[] bytesToDecrypt;
            boolean linked = false;
            try {
                // First attempt is to XOR the bytes and define the class
                bytesToDecrypt = new byte[classBytes.length];
                for (int j = 0; j < bytesToDecrypt.length; ++j) {
                    bytesToDecrypt[j] = (byte) (classBytes[j] ^ 0x55);
                }
                clazz = this.defineClass(name, bytesToDecrypt, 0, bytesToDecrypt.length);
            } catch (LinkageError linkageError) {
                // If linking fails, we might need to decrypt differently
                linked = true;
                bytesToDecrypt = classBytes;
            }

            // Decrypt the bytes using AES
            Cipher cipher = Cipher.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("\n\u0003\u001eo\f\u0000\u0006g\u001b\rC^X0\u000e\u0006\u0001\u0001\u0005\u0001")));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.CAKE[classIndex], Deobfuscator.decodeWithContext(Deobfuscator.getString("\t\u000e\u0015"))), new IvParameterSpec(iv));
            byte[] finalBytes = cipher.doFinal(bytesToDecrypt);

            if (clazz != null) return clazz;
            if (!linked) return null;

            // If the first defineClass failed, try again with the decrypted bytes
            return this.defineClass(name, finalBytes, 0, finalBytes.length);
        } catch (Exception exception) {
            throw new ClassNotFoundException(name, exception);
        }
    }

    private Cake(boolean flag, String[] args, String s1, String s2) throws Exception {
        this.a = new HashMap<>();
        this.C = new HashMap<>();
        if (!(args != null && flag && s1 != null && s2 != null && s1.equals(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u000e\u0013.'zI\u0013\u0016>(+\t>\";\u0014 \u001a'?\u007f o@\"/\n\u0016(9\u00180"))) && s2.equals(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u00188\f|\u001e%7C\t)933p\u001b~"))))) {
            return;
        }

        byte[] decryptedResource = readAndDecryptMainResource();
        checkAgent();
        loadClassMetadata(decryptedResource);
    }

    private byte[] readAndDecryptMainResource() throws Exception {
        try (DataInputStream dataInputStream = new DataInputStream(Cake.class.getResourceAsStream(Deobfuscator.decodeWithContext(Deobfuscator.getString("dv"))))) {
            byte[] iv = new byte[16];
            dataInputStream.readFully(iv);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[512];
            int n3;
            while ((n3 = dataInputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, n3);
            }
            byte[] encryptedResource = byteArrayOutputStream.toByteArray();
            byte[] keyBytes = Deobfuscator.decodeWithContext(Deobfuscator.getString("+6`0\u0012\u0018#R2\u0000{\u0018\u000b`.<")).getBytes(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0003\u0016\u000b\u0002\u000f")));
            Cipher cipher = Cipher.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("\n\u0003\u001eo\f\u0000\u0006g\u001b\rC^X0\u000e\u0006\u0001\u0001\u0005\u0001")));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, Deobfuscator.decodeWithContext(Deobfuscator.getString("\t\u000e\u0015"))), new IvParameterSpec(iv));
            return cipher.doFinal(encryptedResource);
        }
    }

    private void checkAgent() {
        try {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            List<String> inputArguments = runtimeMXBean.getInputArguments();
            for (String string : inputArguments) {
                if (string.equals(Deobfuscator.decodeWithContext(Deobfuscator.getString(" \u001b\u0016}a\u0004$8'/,*\u00031<*%h@\b\u0003'#+!8+")))) {
                    return;
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void loadClassMetadata(byte[] decryptedResource) throws Exception {
        try (DataInputStream decryptedStream = new DataInputStream(new ByteArrayInputStream(decryptedResource))) {
            byte[] expectedHash = new byte[32];
            decryptedStream.readFully(expectedHash);
            int classCount = decryptedStream.readInt();
            int allClassDataSize = decryptedStream.readInt();
            int partsCount = decryptedStream.readInt();

            this.k = new ByteArrayInputStream[partsCount + 1];
            this.h = new byte[partsCount + 1][];

            byte[] allClassesData = new byte[allClassDataSize];
            decryptedStream.readFully(allClassesData);

            MessageDigest messageDigest = MessageDigest.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("3\u0007\u0003hz~p")));
            messageDigest.reset();
            messageDigest.update(allClassesData);
            byte[] actualHash = messageDigest.digest();

            if (actualHash.length != 32) return;
            for (int j = 0; j < expectedHash.length; ++j) {
                if (expectedHash[j] != actualHash[j]) return;
            }

            try (DataInputStream classMetaStream = new DataInputStream(new ByteArrayInputStream(allClassesData))) {
                this.m = new int[classCount];
                this.f = new int[classCount];
                this.i = new int[classCount];
                this.l = new byte[classCount][];
                this.CAKE = new byte[classCount][];
                for (int j = 0; j < classCount; ++j) {
                    byte type = classMetaStream.readByte();
                    byte[] nameBytes = new byte[classMetaStream.readShort()];
                    classMetaStream.readFully(nameBytes);
                    String className = new String(nameBytes, Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0017\u0011\u000ef~")));
                    this.m[j] = classMetaStream.readByte();
                    this.f[j] = classMetaStream.readInt();
                    this.i[j] = classMetaStream.readInt();
                    this.l[j] = new byte[32];
                    classMetaStream.readFully(this.l[j]);
                    this.CAKE[j] = new byte[16];
                    classMetaStream.readFully(this.CAKE[j]);
                    if (type == 0) {
                        this.a.put(className, j);
                    } else if (type == 1) {
                        this.C.put(className, j);
                    }
                }
            }
            loadClassParts(partsCount);
        }
    }

    private void loadClassParts(int partsCount) throws Exception {
        for (int j = 0; j < partsCount; ++j) {
            try (DataInputStream partStream = new DataInputStream(Cake.class.getResourceAsStream(Deobfuscator.decodeWithContext(Deobfuscator.getString("i")) + (j + 1)))) {
                byte[] partIv = new byte[16];
                partStream.readFully(partIv);
                ByteArrayOutputStream partBaos = new ByteArrayOutputStream();
                byte[] partBuffer = new byte[1024];
                int partBytesRead;
                while ((partBytesRead = partStream.read(partBuffer)) != -1) {
                    partBaos.write(partBuffer, 0, partBytesRead);
                }
                byte[] encryptedPart = partBaos.toByteArray();
                byte[] partKeyBytes = Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0005{\te\n%$n\n\u001en\u000b\r\u0004x>")).getBytes(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0003\u0016\u000b\u0002\u000f")));
                Cipher partCipher = Cipher.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("\n\u0003\u001eo\f\u0000\u0006g\u001b\rC^X0\u000e\u0006\u0001\u0001\u0005\u0001")));
                partCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(partKeyBytes, Deobfuscator.decodeWithContext(Deobfuscator.getString("\t\u000e\u0015"))), new IvParameterSpec(partIv));
                byte[] decryptedPart = partCipher.doFinal(encryptedPart);

                try (DataInputStream decryptedPartStream = new DataInputStream(new ByteArrayInputStream(decryptedPart))) {
                    byte[] partExpectedHash = new byte[32];
                    decryptedPartStream.readFully(partExpectedHash);
                    byte[] partData = new byte[decryptedPartStream.readInt()];
                    decryptedPartStream.readFully(partData);

                    MessageDigest partMd = MessageDigest.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("3\u0007\u0003hz~p")));
                    partMd.reset();
                    partMd.update(partData);
                    byte[] partActualHash = partMd.digest();

                    if (partActualHash.length != 32) return;
                    for (int l = 0; l < partExpectedHash.length; ++l) {
                        if (partExpectedHash[l] != partActualHash[l]) return;
                    }
                    this.k[j + 1] = new ByteArrayInputStream(partData);
                    this.h[j + 1] = partData;
                }
            }
        }
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        // Remap resource name
        String resourceName = name.replace(Deobfuscator.decodeWithContext(Deobfuscator.getString("\u001a")), Deobfuscator.decodeWithContext(Deobfuscator.getString("i")));
        try {
            // Check if we are responsible for this resource
            if (!this.C.containsKey(resourceName)) {
                return super.getResourceAsStream(name);
            }
            int resourceIndex = this.C.get(resourceName);

            if (resourceIndex < 0) {
                return null;
            }
            // Extract IV
            byte[] iv = new byte[16];
            for (int j = 0; j < 16; ++j) {
                iv[j] = this.h[this.m[resourceIndex]][this.f[resourceIndex] + j];
            }
            // Extract encrypted resource bytes
            byte[] resourceBytes = new byte[this.i[resourceIndex]];
            for (int j = 0; j < this.i[resourceIndex]; ++j) {
                resourceBytes[j] = this.h[this.m[resourceIndex]][this.f[resourceIndex] + 16 + j];
            }
            // Verify hash
            MessageDigest messageDigest = MessageDigest.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("3\u0007\u0003hz~p")));
            messageDigest.reset();
            messageDigest.update(resourceBytes);
            byte[] hash = messageDigest.digest();
            for (int j = 0; j < this.l[resourceIndex].length; ++j) {
                if (this.l[resourceIndex][j] != hash[j]) {
                    return null;
                }
            }
            // Decrypt and return as a stream
            Cipher cipher = Cipher.getInstance(Deobfuscator.decodeWithContext(Deobfuscator.getString("\n\u0003\u001eo\f\u0000\u0006g\u001b\rC^X0\u000e\u0006\u0001\u0001\u0005\u0001")));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.CAKE[resourceIndex], Deobfuscator.decodeWithContext(Deobfuscator.getString("\t\u000e\u0015"))), new IvParameterSpec(iv));
            byte[] decryptedBytes = cipher.doFinal(resourceBytes);
            return new ByteArrayInputStream(decryptedBytes);
        } catch (Exception exception) {
            return null;
        }
    }

    private static class Deobfuscator {
        public static String getString(String a) {
            return J(m(C(b(A(F(l(H(L(D(K(E(g(k(G(a)))))))))))))));
        }

        public static String decodeWithContext(String a) {
            StackTraceElement stackTraceElement = new RuntimeException().getStackTrace()[1];
            String string = new StringBuffer(stackTraceElement.getMethodName()).append(stackTraceElement.getClassName()).toString();
            int n2 = a.length();
            int n3 = n2 - 1;
            char[] cArray = new char[n2];
            int n4 = 4 << 4 ^ (3 << 2 ^ 3);
            int n5 = 3 ^ 5;
            int n = string.length() - 1;
            int n6 = n;
            int n7 = n3;
            String string2 = string;
            while (n7 >= 0) {
                int n8 = n3--;
                cArray[n8] = (char) (n5 ^ (a.charAt(n8) ^ string2.charAt(n)));
                if (n3 < 0) break;
                int n9 = n3--;
                cArray[n9] = (char) (n4 ^ (a.charAt(n9) ^ string2.charAt(n)));
                if (--n < 0) {
                    n = n6;
                }
                n7 = n3;
            }
            return new String(cArray);
        }

        public static String G(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            char c = '\u0001';
            int n3 = n2;
            int n4 = (3 ^ 5) << 3 ^ 5;
            while (n3 >= 0) {
                int n5 = n2--;
                cArray[n5] = (char) (a.charAt(n5) ^ n4);
                if (n2 < 0) break;
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ c);
                n3 = n2;
            }
            return new String(cArray);
        }

        public static String m(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = 3 << 3 ^ 2;
            int n4 = n2;
            int n5 = (3 ^ 5) << 4 ^ (2 ^ 5) << 1;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String J(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = (3 ^ 5) << 4 ^ (3 << 2 ^ 3);
            int n4 = n2;
            int n5 = 3 << 3 ^ (2 ^ 5);
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String k(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = (3 ^ 5) << 4 ^ 1;
            int n4 = n2;
            int n5 = (3 ^ 5) << 4 ^ (3 << 2 ^ 3);
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String C(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = (3 ^ 5) << 4 ^ (2 ^ 5) << 1;
            int n4 = n2;
            int n5 = (3 ^ 5) << 3 ^ 3;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String D(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = (3 ^ 5) << 3 ^ 1;
            int n4 = n2;
            int n5 = (3 ^ 5) << 4 ^ (3 << 2 ^ 1);
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String b(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = 1 << 3 ^ 5;
            int n4 = n2;
            int n5 = (3 ^ 5) << 3 ^ 4;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String l(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = (3 ^ 5) << 4 ^ (2 << 2 ^ 3);
            int n4 = n2;
            int n5 = (2 ^ 5) << 4 ^ 1 << 1;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String K(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = 2 << 3 ^ 1;
            int n4 = n2;
            int n5 = (2 ^ 5) << 3;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String F(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = (2 ^ 5) << 4 ^ 2 << 1;
            int n4 = n2;
            int n5 = 1 << 3 ^ 2;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String L(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = 5 << 4 ^ 4 << 1;
            int n4 = n2;
            int n5 = 5 << 4 ^ (3 << 2 ^ 3);
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String A(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = (3 ^ 5) << 3 ^ 3;
            int n4 = n2;
            int n5 = 3 << 3 ^ 5;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String H(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = 1 << 3;
            int n4 = n2;
            int n5 = (3 ^ 5) << 3 ^ 5;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String E(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = 4 << 4 ^ 4 << 1;
            int n4 = n2;
            int n5 = (3 ^ 5) << 4 ^ 1;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }

        public static String g(String a) {
            int n = a.length();
            int n2 = n - 1;
            char[] cArray = new char[n];
            int n3 = 3;
            int n4 = n2;
            int n5 = (3 ^ 5) << 3 ^ 2;
            while (n4 >= 0) {
                int n6 = n2--;
                cArray[n6] = (char) (a.charAt(n6) ^ n5);
                if (n2 < 0) break;
                int n7 = n2--;
                cArray[n7] = (char) (a.charAt(n7) ^ n3);
                n4 = n2;
            }
            return new String(cArray);
        }
    }
}
