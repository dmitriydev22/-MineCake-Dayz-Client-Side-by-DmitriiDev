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

    
    private static final String KEY_STRING = "j!@#4_H(G*&^%1sF";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding"; 
    private static final String DIGEST_ALGORITHM = "SHA-256"; 
    private static final String CHARSET = "UTF-8"; 

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

           
            String filePath = Paths.get("src", inputFileName).toString();
            
            try (DataInputStream partStream = new DataInputStream(new FileInputStream(filePath))) {
                
                
                byte[] partIv = new byte[16];
                partStream.readFully(partIv);
                System.out.println("Read IV: " + bytesToHex(partIv));

              
                ByteArrayOutputStream partBaos = new ByteArrayOutputStream();
                byte[] partBuffer = new byte[1024];
                int partBytesRead;
                while ((partBytesRead = partStream.read(partBuffer)) != -1) {
                    partBaos.write(partBuffer, 0, partBytesRead);
                }
                byte[] encryptedPart = partBaos.toByteArray();
                System.out.println("Read " + encryptedPart.length + " bytes of encrypted data.");

                
                byte[] partKeyBytes = KEY_STRING.getBytes(CHARSET);
                Cipher partCipher = Cipher.getInstance(TRANSFORMATION);
                partCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(partKeyBytes, ALGORITHM), new IvParameterSpec(partIv));
                
            
                byte[] decryptedPart = partCipher.doFinal(encryptedPart);
                System.out.println("Decryption successful. Total size: " + decryptedPart.length + " bytes.");

             
                try (DataInputStream decryptedPartStream = new DataInputStream(new java.io.ByteArrayInputStream(decryptedPart))) {
                    byte[] expectedPartHash = new byte[32];
                    decryptedPartStream.readFully(expectedPartHash); // Read and discard the hash
                    System.out.println("Read internal hash: " + bytesToHex(expectedPartHash));

                    int resourceDataSize = decryptedPartStream.readInt();
                    System.out.println("Internal metadata says resource size is: " + resourceDataSize);
                    
                    byte[] resourceData = new byte[resourceDataSize];
                    decryptedPartStream.readFully(resourceData);

                   
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
