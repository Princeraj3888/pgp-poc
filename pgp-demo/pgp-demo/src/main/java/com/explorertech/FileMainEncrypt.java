package com.explorertech;

import com.explorertech.util.PgpPainlessUtil;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileMainEncrypt {

    public static void main(String[] args) {

        String resourcePath = "query.iff";
        String filePath = "src/main/resources/query.iff.gpg";

        String encFilePath = "query.iff.gpg";
        String decFilePath = "src/main/resources/decrypted_query_iff_file.iff";
        boolean isEncrypt = true;

        PGPSecretKeyRing secretKeys = null;
        PGPSecretKeyRing pk = null;

        try (InputStream ourKey = Thread.currentThread().getContextClassLoader().getResourceAsStream("privateKey");
             InputStream theirKey = Thread.currentThread().getContextClassLoader().getResourceAsStream("publicKey")) {

            assert ourKey != null;
            secretKeys = PGPainless.readKeyRing().secretKeyRing(ourKey);

            assert theirKey != null;
            pk = PGPainless.readKeyRing().secretKeyRing(theirKey);

            assert secretKeys != null;
            assert pk != null;

        } catch (Exception e) {
            e.printStackTrace();
        }

        if (isEncrypt) {
            encrypt(resourcePath, filePath, secretKeys, pk);
        } else {
            decrypt(encFilePath, decFilePath, pk, secretKeys);
        }
    }

    private static void decrypt(String encFilePath, String decFilePath, PGPSecretKeyRing pk, PGPSecretKeyRing secretKeys) {
        // Obtaining an InputStream to the resource file
        try (InputStream inputStream = FileMainEncrypt.class.getClassLoader().getResourceAsStream(encFilePath);
             OutputStream os = Files.newOutputStream(Paths.get(decFilePath))) {

            if (inputStream != null) {
                PgpPainlessUtil.decryptFile(inputStream,os, pk.getEncoded(),
                        secretKeys.getPublicKey().getEncoded());

                byte[] buffer = new byte[1024];
                int length;
                // Read from the InputStream and write to the FileOutputStream
                while ((length = inputStream.read(buffer)) != -1) {
                    os.write(buffer, 0, length);
                }
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encrypt(String resourcePath, String filePath, PGPSecretKeyRing secretKeys, PGPSecretKeyRing pk) {
        // Obtaining an InputStream to the resource file
        try (InputStream inputStream = FileMainEncrypt.class.getClassLoader().getResourceAsStream(resourcePath);
             OutputStream os = Files.newOutputStream(Paths.get(filePath))) {


            if (inputStream != null) {
                PgpPainlessUtil.encryptFile(inputStream,os, secretKeys.getEncoded(),
                        pk.getPublicKey().getEncoded());

                byte[] buffer = new byte[1024];
                int length;
                // Read from the InputStream and write to the FileOutputStream
                while ((length = inputStream.read(buffer)) != -1) {
                    os.write(buffer, 0, length);
                }
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
