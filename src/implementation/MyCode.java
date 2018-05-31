package implementation;

import code.GuiException;
import x509.v3.CodeV3;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class MyCode extends CodeV3 {


    private static final String KEYSTORE_TYPE = "pkcs12";

    private static final String KEYSTORE_NAME = "ba140645d.p12";

    private static final String KEYSTORE_PASSWORD = "root";


    private KeyStore keyStore;
    
    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }


    private void saveKeyStore(){
        // ako je keystore null nema sta da radimo
        if (keyStore == null)
            return;

        FileOutputStream fos = null;

        try {
            // pozovemo metodu store
            keyStore.store(fos = new FileOutputStream(KEYSTORE_NAME), KEYSTORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }finally {
            if (fos != null)
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
    }
    @Override
    public Enumeration<String> loadLocalKeystore() {

        // tok za citanje iz fajla
        FileInputStream fis = null;

        try {
            // dohvatimo keystore
            keyStore =  KeyStore.getInstance(KEYSTORE_TYPE);

            // fajl sa svim kljucevima
            File keyStoreFile = new File(KEYSTORE_NAME);

            // ako fajl postoji
            if (keyStoreFile.exists())
                keyStore.load(fis = new FileInputStream(keyStoreFile), KEYSTORE_PASSWORD.toCharArray());
            else
                keyStore.load(null, null);

            // vracamo kljuceve
            return keyStore.aliases();

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        } finally{
            if (fis != null)
                try {
                    fis.close();
                } catch (IOException e) {

                }
        }

        // ako dodje do neke greske vracamo null
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        try {

            // moramo da instanciramo novi keystore
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

            // postavimo da je sadrzaj prazan
            keyStore.load(null, null);

            // sacuvamo izmenu
            saveKeyStore();

        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @Override
    public int loadKeypair(String s) {
        return 0;
    }

    @Override
    public boolean saveKeypair(String s) {
        return false;
    }

    @Override
    public boolean removeKeypair(String s) {
        return false;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean importCertificate(String s, String s1) {
        return false;
    }

    @Override
    public boolean exportCertificate(String s, String s1, int i, int i1) {
        return false;
    }

    @Override
    public boolean exportCSR(String s, String s1, String s2) {
        return false;
    }

    @Override
    public String importCSR(String s) {
        return null;
    }

    @Override
    public boolean signCSR(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean importCAReply(String s, String s1) {
        return false;
    }

    @Override
    public boolean canSign(String s) {
        return false;
    }

    @Override
    public String getSubjectInfo(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String s) {
        return null;
    }
}
