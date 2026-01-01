package net.minecraft.client;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.security.MessageDigest;

public class Decryptor {

    // Hardcoded values from Cake.java's obfuscated methods
    private static final String KEY_STRING = "j!@#4_H(G*&^%1sF"; // Corresponds to ,9$#p4@a...
    private static final String ALGORITHM = "AES"; // Corresponds to ^v.
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding"; // Corresponds to .fm?%%B+!a...
    private static final String DIGEST_ALGORITHM = "SHA-256"; // Corresponds to V,CT-.c
    private static final String CHARSET = "UTF-8"; // Corresponds to C*\z.

    public static void main(String[] args) {
        args = new String[]{"0"};
        if (args.length != 1) {
            System.out.println("Usage: java net.minecraft.client.Decryptor <file_to_decrypt>");
            System.out.println("Example: java net.minecraft.client.Decryptor 0");
            return;
        }

        String inputFileName = args[0];
        String outputFileName = "decrypted_" + inputFileName;

        try {
            System.out.println("Starting decryption of file: " + inputFileName);

            // The files are located in the project's root/src, so we adjust the path
            String filePath = Paths.get("src", inputFileName).toString();
            
            try (DataInputStream partStream = new DataInputStream(new FileInputStream(filePath))) {
                
                // 1. Read the 16-byte IV
                byte[] partIv = new byte[16];
                partStream.readFully(partIv);
                System.out.println("Read IV: " + bytesToHex(partIv));

                // 2. Read the rest of the file as encrypted data
                ByteArrayOutputStream partBaos = new ByteArrayOutputStream();
                byte[] partBuffer = new byte[1024];
                int partBytesRead;
                while ((partBytesRead = partStream.read(partBuffer)) != -1) {
                    partBaos.write(partBuffer, 0, partBytesRead);
                }
                byte[] encryptedPart = partBaos.toByteArray();
                System.out.println("Read " + encryptedPart.length + " bytes of encrypted data.");

                // 3. Set up the decryption cipher
                byte[] partKeyBytes = KEY_STRING.getBytes(CHARSET);
                Cipher partCipher = Cipher.getInstance(TRANSFORMATION);
                partCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(partKeyBytes, ALGORITHM), new IvParameterSpec(partIv));
                
                // 4. Decrypt the data
                byte[] decryptedPart = partCipher.doFinal(encryptedPart);
                System.out.println("Decryption successful. Total size: " + decryptedPart.length + " bytes.");

                // 5. The decrypted data itself contains a hash and the actual content.
                // We can skip the hash check for this tool and just extract the payload.
                try (DataInputStream decryptedPartStream = new DataInputStream(new java.io.ByteArrayInputStream(decryptedPart))) {
                    byte[] expectedPartHash = new byte[32];
                    decryptedPartStream.readFully(expectedPartHash); // Read and discard the hash
                    System.out.println("Read internal hash: " + bytesToHex(expectedPartHash));

                    int resourceDataSize = decryptedPartStream.readInt();
                    System.out.println("Internal metadata says resource size is: " + resourceDataSize);
                    
                    byte[] resourceData = new byte[resourceDataSize];
                    decryptedPartStream.readFully(resourceData);

                    // 6. Write the final payload to the output file
                    try (FileOutputStream fos = new FileOutputStream(outputFileName)) {
                        fos.write(resourceData);
                    }
                    System.out.println("Successfully extracted " + resourceData.length + " bytes of payload to: " + outputFileName);
                }
            }
        } catch (Exception e) {
            System.err.println("An error occurred during decryption:");
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
