package net.minecraft.client;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A tool to extract all encrypted classes and resources from the game's data files.
 * This simulates the behavior of Cake.java to use the correct dynamic decryption keys.
 */
public class Extractor {

    // --- Instance variables to hold the decrypted data, mirroring Cake.java ---
    private byte[][] resourcePartsData; // Corresponds to 'a' in Cake
    private Map<String, Integer> classMap; // Corresponds to 'C'
    private byte[][] classKeys; // Corresponds to 'J'
    private Map<String, Integer> resourceMap; // Corresponds to 'I'
    private byte[][] resourceHashes; // Corresponds to 'K'
    private int[] resourcePartIndices; // Corresponds to 'AAAAAAAAAAAA'
    private int[] resourceSizes; // Corresponds to 'l'
    private int[] resourceOffsets; // Corresponds to 'E'
    private final Set<String> usedFilePaths = new HashSet<>();


    public static void main(String[] args) {
        System.out.println("Starting extraction process...");
        try {
            Extractor extractor = new Extractor();
            extractor.loadAllData();
            extractor.dumpAllFiles();
            System.out.println("\nExtraction finished successfully!");
            System.out.println("Check the 'extracted' directory in your project root.");
        } catch (Exception e) {
            System.err.println("\nAn error occurred during extraction:");
            e.printStackTrace();
        }
    }

    /**
     * This is the main logic, copied and adapted from the Cake constructor.
     * It loads and decrypts all game data into memory.
     */
    public void loadAllData() throws Exception {
        this.classMap = new HashMap<>();
        this.resourceMap = new HashMap<>();

        // --- Step 1: Decrypt the main metadata file (same as Cake constructor) ---
        System.out.println("Step 1: Decrypting main metadata...");
        
        // We need to spoof the caller context for the dynamic key generation
        String initCaller = "net.minecraft.client.Cake<init>";

        byte[] decryptedData;
        try (InputStream is = Cake.class.getResourceAsStream(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("\u001ce"))))))))))))))), initCaller))) {
            if (is == null) throw new RuntimeException("Main data file not found!");
            
            DataInputStream dataInputStream = new DataInputStream(is);
            byte[] iv = new byte[16];
            dataInputStream.readFully(iv);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[512];
            int bytesRead;
            while ((bytesRead = dataInputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            byte[] encryptedData = baos.toByteArray();

            byte[] keyBytes = AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("\u0002tMvh\tG]<ePX77V/"))))))))))))))), initCaller).getBytes(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("C*\\z\u001c"))))))))))))))), initCaller));
            Cipher cipher = Cipher.getInstance(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("\u000fm?%%B+!a\u001c'QVU%F=V}\u0012"))))))))))))))), initCaller));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("^v\u0006"))))))))))))))), initCaller)), new IvParameterSpec(iv));
            decryptedData = cipher.doFinal(encryptedData);
        }
        System.out.println("Main metadata decrypted successfully.");

        // --- Step 2: Parse the metadata to get the file map ---
        System.out.println("Step 2: Parsing metadata and building file map...");
        
        DataInputStream mainDataStream = new DataInputStream(new ByteArrayInputStream(decryptedData));
        byte[] expectedHash = new byte[32];
        mainDataStream.readFully(expectedHash);
        int classCount = mainDataStream.readInt();
        int totalResourceSize = mainDataStream.readInt();
        int resourcePartCount = mainDataStream.readInt();

        this.resourcePartsData = new byte[resourcePartCount + 1][];
        byte[] allResourcesData = new byte[totalResourceSize];
        mainDataStream.readFully(allResourcesData);

        MessageDigest md = MessageDigest.getInstance(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("V,CT-\u0006c"))))))))))))))), initCaller));
        if (!MessageDigest.isEqual(expectedHash, md.digest(allResourcesData))) {
            throw new RuntimeException("Hash mismatch for main resource data!");
        }

        DataInputStream resourceInfoStream = new DataInputStream(new ByteArrayInputStream(allResourcesData));
        this.resourcePartIndices = new int[classCount];
        this.resourceOffsets = new int[classCount];
        this.resourceSizes = new int[classCount];
        this.resourceHashes = new byte[classCount][];
        this.classKeys = new byte[classCount][];

        for (int i = 0; i < classCount; ++i) {
            byte type = resourceInfoStream.readByte();
            short nameLen = resourceInfoStream.readShort();
            byte[] nameBytes = new byte[nameLen];
            resourceInfoStream.readFully(nameBytes);
            String resourceName = new String(nameBytes, AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("W-Y\u001em"))))))))))))))), initCaller));

            this.resourcePartIndices[i] = resourceInfoStream.readByte();
            this.resourceOffsets[i] = resourceInfoStream.readInt();
            this.resourceSizes[i] = resourceInfoStream.readInt();
            this.resourceHashes[i] = new byte[32];
            resourceInfoStream.readFully(this.resourceHashes[i]);
            this.classKeys[i] = new byte[16];
            resourceInfoStream.readFully(this.classKeys[i]);

            if (type == 0) this.classMap.put(resourceName, i);
            else if (type == 1) this.resourceMap.put(resourceName, i);
        }
        System.out.println("File map built: " + this.classMap.size() + " classes, " + this.resourceMap.size() + " resources.");

        // --- Step 3: Decrypt all resource parts ---
        System.out.println("Step 3: Decrypting " + resourcePartCount + " resource parts...");
        for (int i = 0; i < resourcePartCount; ++i) {
            String resourcePartName = AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("z"))))))))))))))), initCaller) + (i + 1);
            try (InputStream is = Cake.class.getResourceAsStream(resourcePartName)) {
                if (is == null) throw new RuntimeException("Resource part file not found: " + resourcePartName);
                
                DataInputStream partStream = new DataInputStream(is);
                byte[] partIv = new byte[16];
                partStream.readFully(partIv);

                ByteArrayOutputStream partBaos = new ByteArrayOutputStream();
                byte[] partBuffer = new byte[1024];
                int partBytesRead;
                while ((partBytesRead = partStream.read(partBuffer)) != -1) {
                    partBaos.write(partBuffer, 0, partBytesRead);
                }
                byte[] encryptedPart = partBaos.toByteArray();

                byte[] partKeyBytes = AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K(",9$#p4@a\u0004{EK1S\u0000-"))))))))))))))), initCaller).getBytes(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("C*\\z\u001c"))))))))))))))), initCaller));
                Cipher partCipher = Cipher.getInstance(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("\u000fm?%%B+!a\u001c'QVU%F=V}\u0012"))))))))))))))), initCaller));
                partCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(partKeyBytes, AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("^v\u0006"))))))))))))))), initCaller)), new IvParameterSpec(partIv));
                byte[] decryptedPart = partCipher.doFinal(encryptedPart);

                DataInputStream decryptedPartStream = new DataInputStream(new ByteArrayInputStream(decryptedPart));
                byte[] expectedPartHash = new byte[32];
                decryptedPartStream.readFully(expectedPartHash);
                int resourceDataSize = decryptedPartStream.readInt();
                byte[] resourceData = new byte[resourceDataSize];
                decryptedPartStream.readFully(resourceData);

                MessageDigest partMd = MessageDigest.getInstance(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K("V,CT-\u0006c"))))))))))))))), initCaller));
                if (!MessageDigest.isEqual(expectedPartHash, partMd.digest(resourceData))) {
                    throw new RuntimeException("Hash mismatch for resource part " + (i + 1));
                }
                this.resourcePartsData[i + 1] = resourceData;
                System.out.println(" -> Decrypted and verified part " + (i + 1));
            }
        }
        System.out.println("All data loaded into memory.");
    }

    /**
     * Iterates through the loaded maps and saves every class and resource to disk.
     */
    public void dumpAllFiles() throws Exception {
        File outputDir = new File("extracted");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        System.out.println("\nStep 4: Dumping all files to 'extracted' directory...");
        usedFilePaths.clear();

        // --- Dump Classes ---
        System.out.println("Dumping " + classMap.size() + " classes...");
        for (Map.Entry<String, Integer> entry : classMap.entrySet()) {
            String className = entry.getKey();
            byte[] classBytes = decryptFile(className, true);
            String path = className.replace('.', '/') + ".class";
            saveFileWithCollisionCheck(outputDir, path, classBytes);
        }

        // --- Dump Resources ---
        System.out.println("Dumping " + resourceMap.size() + " resources...");
        for (Map.Entry<String, Integer> entry : resourceMap.entrySet()) {
            String resourceName = entry.getKey();
            byte[] resourceBytes = decryptFile(resourceName, false);
            
            String finalPath;
            int lastDotIndex = resourceName.lastIndexOf('.');
            if (lastDotIndex > 0 && lastDotIndex < resourceName.length() - 1) {
                String basePath = resourceName.substring(0, lastDotIndex);
                String extension = resourceName.substring(lastDotIndex);
                finalPath = basePath.replace('.', '/') + extension;
            } else {
                finalPath = resourceName.replace('.', '/');
            }
            
            saveFileWithCollisionCheck(outputDir, finalPath, resourceBytes);
        }
    }

    private void saveFileWithCollisionCheck(File outputDir, String path, byte[] bytes) throws IOException {
        String finalPath = path;
        int counter = 0;
        while (usedFilePaths.contains(finalPath.toLowerCase())) {
            counter++;
            int dotIndex = path.lastIndexOf(".");
            String basePath = (dotIndex == -1) ? path : path.substring(0, dotIndex);
            String extension = (dotIndex == -1) ? "" : path.substring(dotIndex);
            finalPath = basePath + "" + counter + extension;
        }
        usedFilePaths.add(finalPath.toLowerCase());

        File outputFile = new File(outputDir, finalPath);
        outputFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(bytes);
        }
    }


    /**
     * This logic is copied from findClass and getResourceAsStream to decrypt a single file.
     * @param name The full name of the class or resource.
     * @param isClass True if it's a class, false if it's a resource.
     * @return The decrypted byte array of the file.
     */
    private byte[] decryptFile(String name, boolean isClass) throws Exception {
        Integer index = isClass ? classMap.get(name) : resourceMap.get(name);
        if (index == null) {
            throw new RuntimeException("Could not find " + (isClass ? "class" : "resource") + " in map: " + name);
        }

        String caller = isClass ? "net.minecraft.client.CakefindClass" : "net.minecraft.client.CakegetResourceAsStream";

        byte[] iv = new byte[16];
        System.arraycopy(this.resourcePartsData[this.resourcePartIndices[index]], this.resourceOffsets[index], iv, 0, 16);

        byte[] encryptedFile = new byte[this.resourceSizes[index]];
        System.arraycopy(this.resourcePartsData[this.resourcePartIndices[index]], this.resourceOffsets[index] + 16, encryptedFile, 0, this.resourceSizes[index]);

        MessageDigest md = MessageDigest.getInstance(AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K(isClass ? "T$KS*K." : "J OA8U0"))))))))))))))), caller));
        if (!MessageDigest.isEqual(this.resourceHashes[index], md.digest(encryptedFile))) {
            throw new RuntimeException("Hash mismatch for file: " + name);
        }

        if (isClass) {
            byte[] xoredBytes = new byte[encryptedFile.length];
            for (int j = 0; j < xoredBytes.length; ++j) {
                xoredBytes[j] = (byte) (encryptedFile[j] ^ 0x55);
            }

            if (xoredBytes.length > 4 &&
                xoredBytes[0] == (byte) 0xCA &&
                xoredBytes[1] == (byte) 0xFE &&
                xoredBytes[2] == (byte) 0xBA &&
                xoredBytes[3] == (byte) 0xBE) {
                return xoredBytes;
            }
        }

        String transformation = AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K(isClass ? ")K8\"'@ *9D\r{TW-N:Q0_" : "/M;!\u000fh=7\u000es:LJI)J(C.A"))))))))))))))), caller);
        String algo = AAAAAAAAAAA_spoofed(a(i(b(k(F(G(H(g(E(B(I(A(D(C(K(isClass ? "Y;K" : "K%U"))))))))))))))), caller);
        
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.classKeys[index], algo), new IvParameterSpec(iv));
        return cipher.doFinal(encryptedFile);
    }

    // --- All deobfuscation methods copied from Cake.java ---

    private static String AAAAAAAAAAA_spoofed(String a, String caller) {
        String string = caller;
        int n2 = a.length();
        int n3 = n2 - 1;
        char[] cArray = new char[n2];
        int n4 = 3 << 3;
        int n5 = 4 << 3 ^ 1;
        int n = string.length() - 1;
        int n6 = n;
        int n7 = n3;
        while (n7 >= 0) {
            int n8 = n3--;
            cArray[n8] = (char) (n5 ^ (a.charAt(n8) ^ string.charAt(n)));
            if (n3 < 0) break;
            int n9 = n3--;
            cArray[n9] = (char) (n4 ^ (a.charAt(n9) ^ string.charAt(n)));
            if (--n < 0) n = n6;
            n7 = n3;
        }
        return new String(cArray);
    }
    
    public static String C(String a) {
        int n = a.length();
        int n2 = n - 1;
        char[] cArray = new char[n];
        int n3 = (3 ^ 5) << 4 ^ (2 ^ 5) << 1;
        int n4 = n2;
        int n5 = 3 << 3 ^ 2;
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
        int n3 = 4 << 4 ^ 2 << 1;
        int n4 = n2;
        int n5 = (3 ^ 5) << 4 ^ 5 << 1;
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
        int n3 = 5 << 4 ^ (2 ^ 5) << 1;
        int n4 = n2;
        int n5 = 5 << 3 ^ (3 ^ 5);
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
        int n3 = 5 << 4 ^ 1 << 1;
        int n4 = n2;
        int n5 = 4 << 4 ^ 1;
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
        int n3 = 4 << 4 ^ (2 ^ 5);
        int n4 = n2;
        int n5 = (2 ^ 5) << 3 ^ 5;
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

    public static String G(String a) {
        int n = a.length();
        int n2 = n - 1;
        char[] cArray = new char[n];
        int n3 = 4 << 4 ^ (2 << 2 ^ 1);
        int n4 = n2;
        int n5 = 5 << 4 ^ (2 ^ 5);
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

    public static String I(String a) {
        int n = a.length();
        int n2 = n - 1;
        char[] cArray = new char[n];
        int n3 = 5 << 4 ^ 5 << 1;
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

    public static String a(String a) {
        int n = a.length();
        int n2 = n - 1;
        char[] cArray = new char[n];
        int n3 = 3 << 3 ^ 4;
        int n4 = n2;
        int n5 = 5 << 3;
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
        int n3 = (3 ^ 5) << 4 ^ (3 << 2 ^ 3);
        int n4 = n2;
        int n5 = 4 << 4 ^ 3;
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
        int n3 = (3 ^ 5) << 4 ^ 3;
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

    public static String i(String a) {
        int n = a.length();
        int n2 = n - 1;
        char[] cArray = new char[n];
        int n3 = 4 << 3 ^ 3;
        int n4 = n2;
        int n5 = (3 ^ 5) << 4 ^ 3;
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
        int n3 = (2 ^ 5) << 4 ^ 4 << 1;
        int n4 = n2;
        int n5 = 4 << 3 ^ (3 ^ 5);
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
        int n3 = (3 ^ 5) << 4 ^ 5 << 1;
        int n4 = n2;
        int n5 = (3 ^ 5) << 4 ^ 3;
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
        int n3 = (2 ^ 5) << 4 ^ 4 << 1;
        int n4 = n2;
        int n5 = 3 << 3 ^ (3 ^ 5);
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
    
    public static String B(String a) {
        int n = a.length();
        int n2 = n - 1;
        char[] cArray = new char[n];
        int n3 = (2 ^ 5) << 3 ^ (3 ^ 5);
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
}
