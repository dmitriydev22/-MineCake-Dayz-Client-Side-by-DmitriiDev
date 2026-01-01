package org.minecake;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Dumper {

    private static final String EXTRACT_DIR = "extract";
    private static final Set<String> usedFilePaths = new HashSet<>();

    public static void main(String[] args) throws Exception {
        // Create extract directory
        Files.createDirectories(Paths.get(EXTRACT_DIR));

        // --- Correctly deobfuscate strings by recreating the context ---
        String res0_name = Deobfuscator.decodeWithContext(Deobfuscator.getString("dv"), "readAndDecryptMainResource", "org.minecake.Cake");
        String key1_str = Deobfuscator.decodeWithContext(Deobfuscator.getString("+6`0\u0012\u0018#R2\u0000{\u0018\u000b`.<"), "readAndDecryptMainResource", "org.minecake.Cake");
        String key1_encoding = Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0003\u0016\u000b\u0002\u000f"), "readAndDecryptMainResource", "org.minecake.Cake");
        String cipher_algo = Deobfuscator.decodeWithContext(Deobfuscator.getString("\n\u0003\u001eo\f\u0000\u0006g\u001b\rC^X0\u000e\u0006\u0001\u0001\u0005\u0001"), "readAndDecryptMainResource", "org.minecake.Cake");
        String key_algo = Deobfuscator.decodeWithContext(Deobfuscator.getString("\t\u000e\u0015"), "readAndDecryptMainResource", "org.minecake.Cake");
        String hash_algo = Deobfuscator.decodeWithContext(Deobfuscator.getString("3\u0007\u0003hz~p"), "loadClassMetadata", "org.minecake.Cake");
        String res_part_prefix = Deobfuscator.decodeWithContext(Deobfuscator.getString("i"), "loadClassParts", "org.minecake.Cake");
        String key2_str = Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0005{\te\n%$n\n\u001en\u000b\r\u0004x>"), "loadClassParts", "org.minecake.Cake");
        String name_encoding = Deobfuscator.decodeWithContext(Deobfuscator.getString("\u0017\u0011\u000ef~"), "loadClassMetadata", "org.minecake.Cake");

        // --- 1. Read and decrypt main resource (file '0') ---
        byte[] decryptedResource;
        try (DataInputStream dataInputStream = new DataInputStream(new FileInputStream("src" + res0_name))) {
            byte[] iv = new byte[16];
            dataInputStream.readFully(iv);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[512];
            int n3;
            while ((n3 = dataInputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, n3);
            }
            byte[] encryptedResource = byteArrayOutputStream.toByteArray();
            byte[] keyBytes = key1_str.getBytes(key1_encoding);
            Cipher cipher = Cipher.getInstance(cipher_algo);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, key_algo), new IvParameterSpec(iv));
            decryptedResource = cipher.doFinal(encryptedResource);
        }

        // --- 2. Load class metadata ---
        Map<String, Integer> classMap = new HashMap<>();
        Map<String, Integer> resourceMap = new HashMap<>();
        int[] m, f, i;
        byte[][] l, CAKE;
        int partsCount;

        try (DataInputStream decryptedStream = new DataInputStream(new ByteArrayInputStream(decryptedResource))) {
            byte[] expectedHash = new byte[32];
            decryptedStream.readFully(expectedHash);
            int classCount = decryptedStream.readInt();
            int allClassDataSize = decryptedStream.readInt();
            partsCount = decryptedStream.readInt();

            byte[] allClassesData = new byte[allClassDataSize];
            decryptedStream.readFully(allClassesData);

            MessageDigest messageDigest = MessageDigest.getInstance(hash_algo);
            messageDigest.update(allClassesData);
            byte[] actualHash = messageDigest.digest();

            for (int j = 0; j < expectedHash.length; ++j) {
                if (expectedHash[j] != actualHash[j]) {
                    System.err.println("[-] Hash mismatch for metadata!");
                    return;
                }
            }

            try (DataInputStream classMetaStream = new DataInputStream(new ByteArrayInputStream(allClassesData))) {
                m = new int[classCount];
                f = new int[classCount];
                i = new int[classCount];
                l = new byte[classCount][];
                CAKE = new byte[classCount][];
                for (int j = 0; j < classCount; ++j) {
                    byte type = classMetaStream.readByte();
                    byte[] nameBytes = new byte[classMetaStream.readShort()];
                    classMetaStream.readFully(nameBytes);
                    String name = new String(nameBytes, name_encoding);
                    m[j] = classMetaStream.readByte();
                    f[j] = classMetaStream.readInt();
                    i[j] = classMetaStream.readInt();
                    l[j] = new byte[32];
                    classMetaStream.readFully(l[j]);
                    CAKE[j] = new byte[16];
                    classMetaStream.readFully(CAKE[j]);
                    if (type == 0) {
                        classMap.put(name, j);
                    } else if (type == 1) {
                        resourceMap.put(name, j);
                    }
                }
            }
        }

        // --- 3. Load class parts ---
        byte[][] h = new byte[partsCount + 1][];
        for (int j = 0; j < partsCount; ++j) {
            try (DataInputStream partStream = new DataInputStream(new FileInputStream("src" + res_part_prefix + (j + 1)))) {
                byte[] partIv = new byte[16];
                partStream.readFully(partIv);
                ByteArrayOutputStream partBaos = new ByteArrayOutputStream();
                byte[] partBuffer = new byte[1024];
                int partBytesRead;
                while ((partBytesRead = partStream.read(partBuffer)) != -1) {
                    partBaos.write(partBuffer, 0, partBytesRead);
                }
                byte[] encryptedPart = partBaos.toByteArray();
                byte[] partKeyBytes = key2_str.getBytes(key1_encoding);
                Cipher partCipher = Cipher.getInstance(cipher_algo);
                partCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(partKeyBytes, key_algo), new IvParameterSpec(partIv));
                byte[] decryptedPart = partCipher.doFinal(encryptedPart);

                try (DataInputStream decryptedPartStream = new DataInputStream(new ByteArrayInputStream(decryptedPart))) {
                    byte[] partExpectedHash = new byte[32];
                    decryptedPartStream.readFully(partExpectedHash);
                    byte[] partData = new byte[decryptedPartStream.readInt()];
                    decryptedPartStream.readFully(partData);

                    MessageDigest partMd = MessageDigest.getInstance(hash_algo);
                    partMd.update(partData);
                    byte[] partActualHash = partMd.digest();

                    boolean hashOk = true;
                    for (int k = 0; k < partExpectedHash.length; ++k) {
                        if (partExpectedHash[k] != partActualHash[k]) {
                             System.err.println("[-] Hash mismatch for part " + (j + 1));
                             hashOk = false;
                             break;
                        }
                    }
                    if(hashOk) {
                        h[j + 1] = partData;
                    }
                }
            }
        }

        System.out.println("[+] Found " + classMap.size() + " classes and " + resourceMap.size() + " resources.");
        usedFilePaths.clear();

        // --- 4. Decrypt and dump classes ---
        for (Map.Entry<String, Integer> entry : classMap.entrySet()) {
            String className = entry.getKey();
            int index = entry.getValue();
            dumpEntry(className, index, h, m, f, i, l, CAKE, hash_algo, cipher_algo, key_algo, true);
        }

        // --- 5. Decrypt and dump resources ---
        for (Map.Entry<String, Integer> entry : resourceMap.entrySet()) {
            String resourceName = entry.getKey();
            int index = entry.getValue();
            dumpEntry(resourceName, index, h, m, f, i, l, CAKE, hash_algo, cipher_algo, key_algo, false);
        }
        
        System.out.println("[+] Done! Files extracted to '" + EXTRACT_DIR + "' directory.");
    }

    private static void dumpEntry(String name, int index, byte[][] h, int[] m, int[] f, int[] i, byte[][] l, byte[][] CAKE, String hash_algo, String cipher_algo, String key_algo, boolean isClass) {
        String filePath;
        if (isClass) {
            filePath = EXTRACT_DIR + "/" + name.replace('.', '/') + ".class";
        } else {
            filePath = EXTRACT_DIR + "/" + name;
        }

        try {
            if (h[m[index]] == null) {
                System.err.println("[-] Skipping " + name + " because its data part was not loaded (hash mismatch?).");
                return;
            }
            
            // Extract IV
            byte[] iv = new byte[16];
            System.arraycopy(h[m[index]], f[index], iv, 0, 16);

            // Extract encrypted bytes
            byte[] encryptedBytes = new byte[i[index]];
            System.arraycopy(h[m[index]], f[index] + 16, encryptedBytes, 0, i[index]);

            // Verify hash
            MessageDigest messageDigest = MessageDigest.getInstance(hash_algo);
            messageDigest.update(encryptedBytes);
            byte[] hash = messageDigest.digest();
            for (int j = 0; j < l[index].length; ++j) {
                if (l[index][j] != hash[j]) {
                    System.err.println("[-] Hash mismatch for: " + name);
                    return;
                }
            }
            
            byte[] decryptedBytes;
            
            if (isClass) {
                byte[] xoredBytes = new byte[encryptedBytes.length];
                for (int j = 0; j < xoredBytes.length; ++j) {
                    xoredBytes[j] = (byte) (encryptedBytes[j] ^ 0x55);
                }

                if (xoredBytes.length > 4 && xoredBytes[0] == (byte) 0xCA && xoredBytes[1] == (byte) 0xFE && xoredBytes[2] == (byte) 0xBA && xoredBytes[3] == (byte) 0xBE) {
                    decryptedBytes = xoredBytes;
                } else {
                    Cipher cipher = Cipher.getInstance(cipher_algo);
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(CAKE[index], key_algo), new IvParameterSpec(iv));
                    decryptedBytes = cipher.doFinal(encryptedBytes);
                }
            } else {
                Cipher cipher = Cipher.getInstance(cipher_algo);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(CAKE[index], key_algo), new IvParameterSpec(iv));
                decryptedBytes = cipher.doFinal(encryptedBytes);
            }

            // --- NEW: Handle filename collisions on case-insensitive filesystems ---
            String finalPath = filePath;
            int counter = 0;
            while (usedFilePaths.contains(finalPath.toLowerCase())) {
                counter++;
                int dotIndex = filePath.lastIndexOf(".");
                String basePath = (dotIndex == -1) ? filePath : filePath.substring(0, dotIndex);
                String extension = (dotIndex == -1) ? "" : filePath.substring(dotIndex);
                finalPath = basePath + "" + counter + extension;
            }
            usedFilePaths.add(finalPath.toLowerCase());
            // ---

            // Save to file
            File outFile = new File(finalPath);
            outFile.getParentFile().mkdirs();
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                fos.write(decryptedBytes);
            }

            if (!finalPath.equals(filePath)) {
                System.out.println("[+] Extracted (collision '" + name + "'): " + finalPath);
            } else {
                System.out.println("[+] Extracted: " + finalPath);
            }

        } catch (Exception e) {
            System.err.println("[-] Failed to extract: " + name);
            e.printStackTrace();
        }
    }

    private static class Deobfuscator {
        public static String getString(String a) {
            return J(m(C(b(A(F(l(H(L(D(K(E(g(k(G(a)))))))))))))));
        }

        public static String decodeWithContext(String a, String methodName, String className) {
            String string = new StringBuffer(methodName).append(className).toString();
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
