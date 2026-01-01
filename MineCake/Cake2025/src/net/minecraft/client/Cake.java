package net.minecraft.client;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.security.Key;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Cake extends ClassLoader {
    private static final Logger logger = Logger.getLogger(Cake.class.getName());

    static {
        try {
            FileHandler fh = new FileHandler("cake-log.txt", true);
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.setLevel(Level.ALL);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[][] a;
    private Map<String, Integer> C;
    private byte[][] J;
    private Map<String, Integer> I;
    private byte[][] K;
    private ByteArrayInputStream[] g;
    private int[] l;
    private int[] E;
    private int[] AAAAAAAAAAAA;

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

    private Cake(boolean flag, String[] args, String mainClass, String version) throws Exception {
        logger.info("Cake constructor: Initializing...");
        this.C = new HashMap<>();
        this.I = new HashMap<>();

        if (!(args != null && flag && mainClass != null && version != null &&
              mainClass.equals(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("3E\u0003a\u0012J3]\u0000}H\u0001;L\u001a^\tX\ny\u00051\u000bO,J!V\u0014n`#"))))))))))))))))) &&
              version.equals(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("1z!:d4SL\u0007L\u0012s\u000f'cm"))))))))))))))))))) {
            logger.severe("Cake constructor: Validation of mainClass or version failed. Aborting initialization.");
            return;
        }
        logger.info("Cake constructor: Validation passed.");

        try (DataInputStream dataInputStream = new DataInputStream(Cake.class.getResourceAsStream(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("\u001ce"))))))))))))))))))) {
            if (dataInputStream == null) {
                logger.severe("Cake constructor: Main data file not found! Aborting.");
                return;
            }
            
            byte[] iv = new byte[16];
            dataInputStream.readFully(iv);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[512];
            int bytesRead;
            while ((bytesRead = dataInputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            byte[] encryptedData = baos.toByteArray();

            byte[] keyBytes = Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("\u0002tMvh\tG]<ePX77V/")))))))))))))))).getBytes(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("C*\\z\u001c")))))))))))))))));

            Cipher cipher = Cipher.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("\u000fm?%%B+!a\u001c'QVU%F=V}\u0012")))))))))))))))));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("^v\u0006"))))))))))))))))), new IvParameterSpec(iv));
            byte[] decryptedData = cipher.doFinal(encryptedData);

            logger.warning("Cake constructor: Java agent check has been bypassed for debugging.");

            try (DataInputStream mainDataStream = new DataInputStream(new ByteArrayInputStream(decryptedData))) {
                byte[] expectedHash = new byte[32];
                mainDataStream.readFully(expectedHash);
                int classCount = mainDataStream.readInt();
                int totalResourceSize = mainDataStream.readInt();
                int resourcePartCount = mainDataStream.readInt();
                logger.info("Cake constructor: Metadata: classCount=" + classCount + ", totalResourceSize=" + totalResourceSize + ", resourcePartCount=" + resourcePartCount);

                this.g = new ByteArrayInputStream[resourcePartCount + 1];
                this.a = new byte[resourcePartCount + 1][];

                byte[] allResourcesData = new byte[totalResourceSize];
                mainDataStream.readFully(allResourcesData);

                MessageDigest md = MessageDigest.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("V,CT-\u0006c")))))))))))))))));
                byte[] actualHash = md.digest(allResourcesData);

                if (!MessageDigest.isEqual(expectedHash, actualHash)) {
                    logger.severe("Cake constructor: Hash mismatch for main resource data. Aborting initialization.");
                    return;
                }
                logger.info("Cake constructor: Main resource data hash verified.");

                try (DataInputStream resourceInfoStream = new DataInputStream(new ByteArrayInputStream(allResourcesData))) {
                    this.AAAAAAAAAAAA = new int[classCount];
                    this.E = new int[classCount];
                    this.l = new int[classCount];
                    this.K = new byte[classCount][];
                    this.J = new byte[classCount][];

                    for (int i = 0; i < classCount; ++i) {
                        byte type = resourceInfoStream.readByte();
                        short nameLen = resourceInfoStream.readShort();
                        byte[] nameBytes = new byte[nameLen];
                        resourceInfoStream.readFully(nameBytes);
                        String resourceName = new String(nameBytes, Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("W-Y\u001em")))))))))))))))));

                        int flag1 = resourceInfoStream.readByte();
                        int offset = resourceInfoStream.readInt();
                        int size = resourceInfoStream.readInt();
                        byte[] hash = new byte[32];
                        resourceInfoStream.readFully(hash);
                        byte[] ivSpec = new byte[16];
                        resourceInfoStream.readFully(ivSpec);

                        this.AAAAAAAAAAAA[i] = flag1;
                        this.E[i] = offset;
                        this.l[i] = size;
                        this.K[i] = hash;
                        this.J[i] = ivSpec;

                        if (type == 0) {
                            this.C.put(resourceName, i);
                        } else if (type == 1) {
                            this.I.put(resourceName, i);
                        }
                    }
                    logger.info("Cake constructor: Loaded " + this.C.size() + " class definitions and " + this.I.size() + " resource definitions.");
                }

                for (int i = 0; i < resourcePartCount; ++i) {
                    String resourcePartName = Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("z")))))))))))))))) + (i + 1);
                    try (DataInputStream partStream = new DataInputStream(Cake.class.getResourceAsStream(resourcePartName))) {
                        if (partStream == null) {
                            logger.severe("Cake constructor: Resource part file not found: " + resourcePartName + ". Aborting.");
                            return;
                        }
                        
                        byte[] partIv = new byte[16];
                        partStream.readFully(partIv);

                        ByteArrayOutputStream partBaos = new ByteArrayOutputStream();
                        byte[] partBuffer = new byte[1024];
                        int partBytesRead;
                        while ((partBytesRead = partStream.read(partBuffer)) != -1) {
                            partBaos.write(partBuffer, 0, partBytesRead);
                        }
                        byte[] encryptedPart = partBaos.toByteArray();

                        byte[] partKeyBytes = Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K(",9$#p4@a\u0004{EK1S\u0000-")))))))))))))))).getBytes(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("C*\\z\u001c")))))))))))))))));

                        Cipher partCipher = Cipher.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("\u000fm?%%B+!a\u001c'QVU%F=V}\u0012")))))))))))))))));
                        partCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(partKeyBytes, Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("^v\u0006"))))))))))))))))), new IvParameterSpec(partIv));
                        byte[] decryptedPart = partCipher.doFinal(encryptedPart);

                        try (DataInputStream decryptedPartStream = new DataInputStream(new ByteArrayInputStream(decryptedPart))) {
                            byte[] expectedPartHash = new byte[32];
                            decryptedPartStream.readFully(expectedPartHash);

                            int resourceDataSize = decryptedPartStream.readInt();
                            byte[] resourceData = new byte[resourceDataSize];
                            decryptedPartStream.readFully(resourceData);

                            MessageDigest partMd = MessageDigest.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("V,CT-\u0006c")))))))))))))))));
                            byte[] actualPartHash = partMd.digest(resourceData);

                            if (!MessageDigest.isEqual(expectedPartHash, actualPartHash)) {
                                logger.severe("Cake constructor: Hash mismatch for resource part " + (i + 1) + ". Aborting initialization.");
                                return;
                            }
                            
                            try {
                                logger.info("ARCHIVE_INSPECTOR: Inspecting decrypted part " + (i + 1));
                                ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(resourceData));
                                ZipEntry zipEntry;
                                int fileCount = 0;
                                while ((zipEntry = zis.getNextEntry()) != null) {
                                    logger.info("ARCHIVE_INSPECTOR: Found file in part " + (i + 1) + ": " + zipEntry.getName());
                                    zis.closeEntry();
                                    fileCount++;
                                }
                                logger.info("ARCHIVE_INSPECTOR: Found " + fileCount + " total files in part " + (i + 1));
                            } catch (Exception e) {
                                logger.log(Level.WARNING, "ARCHIVE_INSPECTOR: Failed to inspect part " + (i + 1) + " as a zip archive.", e);
                            }
                          -

                            this.g[i + 1] = new ByteArrayInputStream(resourceData);
                            this.a[i + 1] = resourceData;
                        }
                    }
                }
                logger.info("Cake constructor: All resource parts loaded and verified.");
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "An unexpected error occurred during Cake initialization.", e);
            throw e;
        }
        logger.info("Cake constructor: Initialization finished successfully.");
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        name = name.replace(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("Z")))))))))))))))), Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K(")")))))))))))))))));
        try {
            Integer indexObj = this.I.get(name);
            if (indexObj == null) {
                return null;
            }
            int index = indexObj;

            if (index < 0) {
                return null;
            }

            byte[] iv = new byte[16];
            System.arraycopy(this.a[this.AAAAAAAAAAAA[index]], this.E[index], iv, 0, 16);

            byte[] encryptedResource = new byte[this.l[index]];
            System.arraycopy(this.a[this.AAAAAAAAAAAA[index]], this.E[index] + 16, encryptedResource, 0, this.l[index]);

            MessageDigest md = MessageDigest.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("J OA8U0")))))))))))))))));
            byte[] actualHash = md.digest(encryptedResource);

            if (!MessageDigest.isEqual(this.K[index], actualHash)) {
                return null;
            }

            Cipher cipher = Cipher.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("/M;!\u000fh=7\u000es:LJI)J(C.A")))))))))))))))));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.J[index], Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("K%U"))))))))))))))))), new IvParameterSpec(iv));
            byte[] decryptedResource = cipher.doFinal(encryptedResource);
            return new ByteArrayInputStream(decryptedResource);

        } catch (Exception e) {
            return null;
        }
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

    public static String AAAAAAAAAAAA(String a) {
        StackTraceElement stackTraceElement = new RuntimeException().getStackTrace()[1];
        String string = stackTraceElement.getClassName() + stackTraceElement.getMethodName();
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
            if (--n < 0) {
                n = n6;
            }
            n7 = n3;
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

    public static void begin(Object[] a) {
        try {
            logger.info("begin: Starting execution...");
            boolean flag = (Boolean) a[0];
            String[] args = (String[]) a[1];
            String mainClass = (String) a[2];
            String version = (String) a[3];

            if (!(args != null && flag && mainClass != null && version != null &&
                  mainClass.equals(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("<J\u0006d\u001eF8V\u001ag\u0012[V!8|\u0003R\u0004w\\h\u0000D'A/X\ts0s"))))))))))))))))) &&
                  version.equals(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K(";p/4=mXG\fG\u001c}\u0012:3="))))))))))))))))))) {
                logger.severe("begin: Initial validation failed. The mainClass or version is incorrect. Game cannot start.");
                return;
            }

            if (args.length >= 3 && args[0] != null && args[1] != null && args[2] != null) {
                if (args[0].equals(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("\u0012_\u0011|}B\u0007K\"H(-GgZJR4A6\u0007k")))))))))))))))))) {
                    logger.info("begin: Arguments validated, creating Cake class loader.");
                    Cake cake = new Cake(flag, args, mainClass, version);
                    
                    String gameClassName = Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("#c\u000e`"))))))))))))))));
                    logger.info("begin: Attempting to find class: " + gameClassName);
                    Class<?> clazz = cake.findClass(gameClassName);

                    if (clazz != null) {
                        logger.info("begin: Class '" + gameClassName + "' found. Proceeding with launch.");
                        StringBuilder sb = new StringBuilder();
                        for (int i = args[2].length() - 1; i >= 0; --i) {
                            char c = args[2].charAt(i);
                            switch (c) {
                                case 'g': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("1"))))))))))))))))); break;
                                case '4': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("b"))))))))))))))))); break;
                                case 'T': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("D"))))))))))))))))); break;
                                case 'A': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("Q"))))))))))))))))); break;
                                case 'R': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("t"))))))))))))))))); break;
                                case 'q': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("W"))))))))))))))))); break;
                                case 'x': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("I"))))))))))))))))); break;
                                case 'L': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("}"))))))))))))))))); break;
                                case '6': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("g"))))))))))))))))); break;
                                case 'b': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("3"))))))))))))))))); break;
                                case '3': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("f"))))))))))))))))); break;
                                case 'c': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("6"))))))))))))))))); break;
                                case 'B': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("="))))))))))))))))); break;
                                case '8': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("G"))))))))))))))))); break;
                                case 'v': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("r"))))))))))))))))); break;
                                case 'w': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("s"))))))))))))))))); break;
                                case 'P': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("P"))))))))))))))))); break;
                                case 'U': sb.append(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("U"))))))))))))))))); break;
                                default: sb.append(c);
                            }
                        }
                        args[2] = sb.toString();
                        args[0] = Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("o2~NB0x GK;\u0013OJ\r)(\r~\fiHW\u0001kK?\u001a,%]#B.Q\u000bLO89Y\u0002,]i\u0015D"))))))))))))))));

                        clazz.getMethod(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("\tc\nk")))))))))))))))), String[].class).invoke(null, (Object) args);
                    } else {
                        // This case should ideally not be reached if findClass throws an exception
                        logger.severe("begin: findClass returned null, but did not throw an exception. Fallback initiated.");
                        Class<?> cakeClass = cake.findClass("net.minecraft.client.Cake");
                        if (cakeClass != null) {
                            cakeClass.getMethod(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("n\u0001e\nk")))))))))))))))), Object[].class).invoke(null, (Object) a);
                        }
                    }
                } else {
                    logger.severe("begin: Argument validation failed: First argument is incorrect. Game cannot start.");
                }
            } else {
                logger.severe("begin: Argument validation failed: Requires at least 3 arguments, but got " + (args != null ? args.length : "null") + ". Game cannot start.");
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "begin: An unexpected error occurred. This might be due to incorrect launch parameters or corrupted game files.", e);
        }
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

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        logger.info("findClass: Attempting to find class '" + name + "'");
        try {
            Integer indexObj = this.C.get(name);
            if (indexObj == null) {
                logger.warning("findClass: Class '" + name + "' not found in custom class map. Delegating to parent class loader.");
                return super.findClass(name);
            }
            logger.info("findClass: Class '" + name + "' found in custom map. Proceeding to decrypt and define.");
            int index = indexObj;

            if (index < 0) {
                logger.warning("findClass: Index for class '" + name + "' is negative. This is unusual. Delegating to parent.");
                return super.findClass(name);
            }

            byte[] iv = new byte[16];
            System.arraycopy(this.a[this.AAAAAAAAAAAA[index]], this.E[index], iv, 0, 16);

            byte[] encryptedClass = new byte[this.l[index]];
            System.arraycopy(this.a[this.AAAAAAAAAAAA[index]], this.E[index] + 16, encryptedClass, 0, this.l[index]);

            MessageDigest md = MessageDigest.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("T$KS*K.")))))))))))))))));
            byte[] actualHash = md.digest(encryptedClass);

            if (!MessageDigest.isEqual(this.K[index], actualHash)) {
                logger.severe("findClass: Hash mismatch for class '" + name + "'. The game files might be corrupted.");
                throw new ClassNotFoundException("Hash mismatch for class " + name);
            }
            logger.info("findClass: Hash for class '" + name + "' verified.");

            Cipher cipher = Cipher.getInstance(Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K(")K8\"'@ *9D\r{TW-N:Q0_")))))))))))))))));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.J[index], Cake.AAAAAAAAAAAA(Cake.a(Cake.i(Cake.b(Cake.k(Cake.F(Cake.G(Cake.H(Cake.g(Cake.E(Cake.B(Cake.I(Cake.A(Cake.D(Cake.C(Cake.K("Y;K"))))))))))))))))), new IvParameterSpec(iv));
            byte[] decryptedClass = cipher.doFinal(encryptedClass);
            
            logger.info("findClass: Successfully decrypted class '" + name + "'. Defining it now.");
            return defineClass(name, decryptedClass, 0, decryptedClass.length);

        } catch (Exception e) {
            logger.log(Level.SEVERE, "findClass: An exception occurred while trying to find or load class '" + name + "'.", e);
            throw new ClassNotFoundException(name, e);
        }
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
}
