package implementation;

import code.GuiException;
import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;
import gui.Constants;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import x509.v3.CodeV3;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Set;
import java.util.Vector;

import static org.bouncycastle.asn1.x500.style.RFC4519Style.l;
import static org.bouncycastle.asn1.x500.style.RFC4519Style.st;

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


    private static final int KEY_USAGE_DIGITAL_SIGNATURE = 0;

    private static final int KEY_USAGE_CONTENT_COMMITMENT = 1;

    private static final int KEY_USAGE_KEY_ENCIPHERMENT = 2;

    private static final int KEY_USAGE_DATA_ENCIPHERMENT = 3;

    private static final int KEY_USAGE_KEY_AGREEMENT = 4;

    private static final int KEY_USAGE_CERTIFICATE_SIGNING = 5;

    private static final int KEY_USAGE_CRL_SIGNING = 6;

    private static final int KEY_USAGE_ENCIPHER_ONLY = 7;

    private static final int KEY_USAGE_DECIPHER_ONLY = 8;


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

    private void loadBasicCertificateInfo(@NotNull X509Certificate certificate, @Nullable X509Certificate issuer){

        access.setPublicKeyAlgorithm(certificate.getSigAlgName());

        access.setSubjectSignatureAlgorithm(certificate.getSigAlgName());

        access.setSerialNumber(certificate.getSerialNumber().toString());

        access.setNotBefore(certificate.getNotBefore());

        access.setNotAfter(certificate.getNotAfter());

        access.setVersion(certificate.getVersion() == 3? VERSION_3_CODE : VERSION_1_CODE);

        access.setPublicKeyParameter(certificate.getPublicKey() + "");

        access.setPublicKeyParameter("test");

        String issuerName = certificate.getIssuerDN().toString() + " ";

        access.setIssuer(issuerName
                .replaceAll(", ", ",")
                .replaceAll("=", "= ,")
                .replaceAll("  ", " "));

        if (issuer != null)
            access.setIssuerSignatureAlgorithm(issuer.getSigAlgName());
        else
            access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());

        try {
            LdapName ldapName = new LdapName(certificate.getSubjectDN().toString());

            for(String info : Collections.list(ldapName.getAll())) {

                String[] infoTypeAndValue = info.split("=");

                if (infoTypeAndValue.length < 2)
                    continue;

                String infoType = info.split("=")[0];

                String infoValue = info.split("=")[1];

                switch (infoType) {
                    case "CN":
                        access.setSubjectCommonName(infoValue);             break;
                    case "C":
                        access.setSubjectCountry(infoValue);                break;
                    case "L":
                        access.setSubjectLocality(infoValue);               break;
                    case "O":
                        access.setSubjectOrganization(infoValue);           break;
                    case "OU":
                        access.setSubjectOrganizationUnit(infoValue);       break;
                    case "ST":
                        access.setSubjectState(infoValue);                  break;
                }
            }

        } catch (InvalidNameException e) {
            e.printStackTrace();
        }


        //access.setPublicKeyParameter();

    }


    private X509Certificate generateCertificate(KeyPair keyPair){
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("OU=").append(access.getSubjectOrganizationUnit());

        stringBuilder.append(",O=").append(access.getSubjectOrganization());

        stringBuilder.append(",L=").append(access.getSubjectLocality());

        stringBuilder.append(",ST=").append(access.getSubjectState());

        stringBuilder.append(",C=").append(access.getSubjectCountry());

        stringBuilder.append(",CN=").append(access.getSubjectCommonName());

        X500Name x500Name = new X500Name(stringBuilder.toString());

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                x500Name,
                new BigInteger(access.getSerialNumber()),
                access.getNotBefore(),
                access.getNotAfter(),
                x500Name,
                keyPair.getPublic()
        );


        String dateOfBirth = access.getDateOfBirth();
        String placeOfBirth = access.getSubjectDirectoryAttribute(Constants.POB);
        String countryOfCitizenship = access.getSubjectDirectoryAttribute(Constants.COC);
        String gender = access.getGender();

        Vector<Attribute> attributes = new Vector<>();

        if (dateOfBirth.length() > 0)
            attributes.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new DERGeneralString(dateOfBirth))));

        if (placeOfBirth.length() > 0)
            attributes.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet(new DERGeneralString(placeOfBirth))));

        if (countryOfCitizenship.length() > 0)
            attributes.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DERGeneralString(countryOfCitizenship))));

        if (gender.length() > 0)
            attributes.add(new Attribute(BCStyle.GENDER, new DERSet(new DERGeneralString(gender))));


        try {
            if (attributes.size() != 0)
                certificateBuilder.addExtension(Extension.subjectDirectoryAttributes,
                        access.isCritical(Constants.SDA),
                        new SubjectDirectoryAttributes(attributes)
                        );

        } catch (CertIOException e) {
            e.printStackTrace();
        }



        boolean[] selectedKeyUsages = access.getKeyUsage();

        int keyUsages = 0;

        if (selectedKeyUsages[KEY_USAGE_DIGITAL_SIGNATURE])
            keyUsages |= KeyUsage.digitalSignature;

        if (selectedKeyUsages[KEY_USAGE_CONTENT_COMMITMENT])
            keyUsages |= KeyUsage.nonRepudiation;

        if (selectedKeyUsages[KEY_USAGE_KEY_ENCIPHERMENT])
            keyUsages |= KeyUsage.keyEncipherment;

        if (selectedKeyUsages[KEY_USAGE_DATA_ENCIPHERMENT])
            keyUsages |= KeyUsage.dataEncipherment;

        if (selectedKeyUsages[KEY_USAGE_KEY_AGREEMENT])
            keyUsages |= KeyUsage.keyAgreement;

        if (selectedKeyUsages[KEY_USAGE_CERTIFICATE_SIGNING])
            keyUsages |= KeyUsage.keyCertSign;

        if (selectedKeyUsages[KEY_USAGE_CRL_SIGNING])
            keyUsages |= KeyUsage.cRLSign;

        if (selectedKeyUsages[KEY_USAGE_ENCIPHER_ONLY])
            keyUsages |= KeyUsage.encipherOnly;

        if (selectedKeyUsages[KEY_USAGE_DECIPHER_ONLY])
            keyUsages |= KeyUsage.decipherOnly;



        KeyUsage keyUsage = new KeyUsage(keyUsages);

        try {
            certificateBuilder.addExtension(Extension.keyUsage,
                    access.isCritical(Constants.KU),
                    keyUsage);
        } catch (CertIOException e) {
            e.printStackTrace();
        }

        int pathLen = 0;

        if (access.getPathLen().length() > 0)
            Integer.parseInt(access.getPathLen());

        boolean isCA = access.isCA();

        BasicConstraints basicConstraints;

        if(isCA)
            basicConstraints = new BasicConstraints(pathLen);
        else
            basicConstraints = new BasicConstraints(false);


        try {
            certificateBuilder.addExtension(Extension.basicConstraints,
                    access.isCritical(Constants.BC),
                    basicConstraints
            );
        } catch (CertIOException e) {
            e.printStackTrace();
        }

        try {
            ContentSigner signer = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm())
                    .build(keyPair.getPrivate());

            return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
        } catch (OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        }


        return null;
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

            Set<String> criticalExtensions = Collections.EMPTY_SET;

            criticalExtensions = certificate.getCriticalExtensionOIDs();

            boolean keyUsageCritical = false;
            boolean subjectDirectoryAttributesCritical = false;
            boolean basicConstraintCritical = false;
            for(String criticalExtension : criticalExtensions){
                if (criticalExtension.equals(Extension.keyUsage.toString()))
                    access.setCritical(Constants.KU, keyUsageCritical = true);
                else if (criticalExtension.equals(Extension.subjectDirectoryAttributes.toString()))
                    access.setCritical(Constants.SDA, subjectDirectoryAttributesCritical = true);
                else if (criticalExtension.equals(Extension.basicConstraints.toString()))
                    access.setCritical(Constants.BC, basicConstraintCritical = true);
            }


            boolean[] keyUsage = certificate.getKeyUsage();

            if (keyUsage != null)
                access.setKeyUsage(keyUsage);
            else if (keyUsageCritical)
                return KEYPAIR_ERROR_CODE;

            byte[] sdaBytes = certificate.getExtensionValue(Extension.subjectDirectoryAttributes.toString());

            if (sdaBytes == null && subjectDirectoryAttributesCritical)
                return KEYPAIR_ERROR_CODE;

            if (sdaBytes != null){
                SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes
                        .getInstance(X509ExtensionUtil.fromExtensionValue(sdaBytes));

                Vector<Attribute> attributeVector = subjectDirectoryAttributes.getAttributes();

                for(Attribute attribute : attributeVector){
                    String attributeType = attribute.getAttrType().toString();

                    String attributeValue = attribute.getAttrValues().toString();

                    attributeValue = attributeValue.substring(1, attributeValue.length() - 1);

                    if (attributeType.equals(BCStyle.PLACE_OF_BIRTH.toString()))
                        access.setSubjectDirectoryAttribute(Constants.POB, attributeValue);
                    else if (attributeType.equals(BCStyle.COUNTRY_OF_CITIZENSHIP.toString()))
                        access.setSubjectDirectoryAttribute(Constants.COC, attributeValue);
                    else if (attributeType.equals(BCStyle.GENDER.toString()))
                        access.setGender(attributeValue);
                    else if (attribute.equals(BCStyle.DATE_OF_BIRTH.toString()))
                        access.setDateOfBirth(attributeValue);
                }
            }


            int basicConstraints = certificate.getBasicConstraints();

            // Ukoliko nije CA, vraca se vrednost -1,
            if (basicConstraints != -1)
                access.setPathLen(basicConstraints == Integer.MAX_VALUE ? "" + basicConstraints : "");

            access.setCA(basicConstraints != -1);

            if (certificate.getSubjectDN().equals(certificate.getIssuerDN()))
                return KEYPAIR_UNSIGNED_CODE;

            if (keyStore.isCertificateEntry(keyPairName)){

                Enumeration<String> enumeration = keyStore.aliases();

                while(enumeration.hasMoreElements()){
                    String key = enumeration.nextElement();

                    if (key.equals(keyPairName))
                        continue;

                    X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(key);

                    try {
                        certificate.verify(x509Certificate.getPublicKey());

                        return KEYPAIR_TRUSTED_CERT;
                    } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {

                    }
                }

            }

            return KEYPAIR_SIGNED_CODE;
        } catch (KeyStoreException | IOException e) {
            e.printStackTrace();
        }


        return KEYPAIR_ERROR_CODE;
    }

    @Override
    public boolean saveKeypair(String keyPairName) {

        try {
            if (keyStore.containsAlias(keyPairName))
                return false;

            // kreiramo instancu generatora kljuceva
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(access.getPublicKeyAlgorithm());

            keyPairGenerator.initialize(Integer.parseInt(access.getPublicKeyParameter()));

            System.out.println(access.getPublicKeyParameter());

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509Certificate x509Certificate = generateCertificate(keyPair);


            keyStore.setKeyEntry(keyPairName, keyPair.getPrivate(),
                    KEYSTORE_PASSWORD.toCharArray(),
                    new X509Certificate[]{x509Certificate});

            saveKeyStore();

            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

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
