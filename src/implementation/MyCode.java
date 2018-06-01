package implementation;

import code.GuiException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import x509.v3.CodeV3;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;

public class MyCode extends CodeV3 {


    private static final String KEYSTORE_TYPE = "pkcs12";

    private static final String KEYSTORE_NAME = "ba140645d.p12";

    private static final String KEYSTORE_PASSWORD = "root";


    private static final int KEYPAIR_ERROR_CODE = -1;

    private static final int KEYPAIR_UNSIGNED_CODE = 0;

    private static final int KEYPAIR_SIGNED_CODE = 1;

    private static final int KEYPAIR_TRUSTED_CERT = 2;


    private static final int VERSION_3_CODE = 2;

    private static final int VERSION_1_CODE = 1;


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

    private void loadBasicCertificateInfo(X509Certificate certificate, X509Certificate issuer){

        access.setPublicKeyAlgorithm(certificate.getSigAlgName());

        access.setSubjectSignatureAlgorithm(certificate.getSigAlgName());

        access.setSerialNumber(certificate.getSerialNumber().toString());

        access.setNotBefore(certificate.getNotBefore());

        access.setNotAfter(certificate.getNotAfter());

        access.setVersion(certificate.getVersion() == 3? VERSION_3_CODE : VERSION_1_CODE);

        for(String info : Collections.list())
        try {
            LdapName ldapName = new LdapName(certificate.getSubjectDN().toString());

            String infoType = info.split("=")[0];

            String infoValue = info.split("=")[1];

            switch(infoType){
                case "CN":  access.setSubjectCommonName(infoValue);         break;
                case "C":   access.setSubjectCountry(infoValue);            break;
                case "L":   access.setSubjectLocality(infoValue);           break;
                case "O":   access.setSubjectOrganization(infoValue);       break;
                case "OU":  access.setSubjectOrganizationUnit(infoValue);   break;
                case "ST":  access.setSubjectState(infoValue);              break;
            }
            
        } catch (InvalidNameException e) {
            e.printStackTrace();
        }


        //access.setPublicKeyParameter();

    }

    @Override
    public Enumeration<String> loadLocalKeystore() {

        // tok za citanje iz fajla
        FileInputStream fis = null;

        try {
            // dohvatimo keystore
            keyStore =  KeyStore.getInstance(KEYSTORE_TYPE, new BouncyCastleProvider());

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
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE, new BouncyCastleProvider());

            // postavimo da je sadrzaj prazan
            keyStore.load(null, null);

            // sacuvamo izmenu
            saveKeyStore();

        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @Override
    public int loadKeypair(String keyPairName) {

        X509Certificate issuerCertificate = null;

        X509Certificate certificate = null;

        Certificate[] chainedCertificates = null;


        try {
            certificate = (X509Certificate) keyStore.getCertificate(keyPairName);

            chainedCertificates = keyStore.getCertificateChain(keyPairName);

            if (chainedCertificates != null)
                issuerCertificate = (X509Certificate) chainedCertificates[0];

            loadBasicCertificateInfo(certificate, issuerCertificate);


        } catch (KeyStoreException e) {
            e.printStackTrace();
        }


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
