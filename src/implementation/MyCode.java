package implementation;

import code.GuiException;
import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;
import gui.Constants;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class MyCode extends CodeV3 {


    private static final String X509_CERTIFICATE_TYPE = "X.509";

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


    private static final Provider BCProvider = new BouncyCastleProvider();

    private KeyStore keyStore;


    private PKCS10CertificationRequest csr = null;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }


    /**
     * Metoda koja sacuva trenutno stanje keystore-a u fajl formata PKCS12
     */
    private void saveKeyStore(){
        // ako je keystore null nema sta da radimo
        if (keyStore == null)
            return;


        try(FileOutputStream fos = new FileOutputStream(KEYSTORE_NAME)){
            // sacuvamo sve u fajl
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    /**
     * Sacuva trenutno stanje zadatog keystore-a u zadati fajl zasticen zadatom sifrom
     * @param keyStore keyStore koji cuvamo
     * @param filePath naziv fajla u koji cuvamo
     * @param password sifra fajla
     */
    private void saveKeyStore(KeyStore keyStore, String filePath, String password){

        try(FileOutputStream fos = new FileOutputStream(filePath)){
            keyStore.store(fos, password.toCharArray());
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            e.printStackTrace();
        }
    }


    /**
     * Reformatira osnovne podatke o sertifikatu zarad ispunjavanja specifikacije GUI-a
     * @param basicInformation informacija o sertifikatu za formatiranje
     * @return formatirane informacije o sertifikatu za GUI
     */
    private String reformatBasicCertInfo(String basicInformation){
        return basicInformation.replaceAll(", ", ",")
                .replaceAll("=,", "= ,")
                .replaceAll("  ", " ");
    }


    /**
     * Metoda koja ucita u GUI osnovne podatke o sertifikatu
     * @param certificate sertifikat iz kojeg citamo
     * @param issuer sertifikat koji ga je potpisao/izdao
     */
    private void loadBasicCertificateInfo(@NotNull X509Certificate certificate, @Nullable X509Certificate issuer){

        // algoritam kojim sertifikat potpisuje
        access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());

        // serijski broj sertifikata
        access.setSerialNumber(certificate.getSerialNumber().toString());

        // datum pocetka vazenja
        access.setNotBefore(certificate.getNotBefore());

        // datum kraja vazenja
        access.setNotAfter(certificate.getNotAfter());

        // verzija sertifikata
        access.setVersion(certificate.getVersion() == 3? VERSION_3_CODE : VERSION_1_CODE);

        // parametri javnog kljuca sertifikata
        access.setPublicKeyParameter(certificate.getPublicKey().toString());

        // osnovni podaci o izdavacu sertifikata
        String issuerName = certificate.getIssuerDN().toString();

        // prikaz osnovnih podataka izdavaca
        // dodajemo space karakter da bi mogli da formatiramo lepo issuer-a za GUI
        access.setIssuer(reformatBasicCertInfo(issuerName + " "));

        // algoritam za potpisivanje izdavaca
        access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
        // citanje osnovnih podataka O sertifikatu
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
    }

    /**
     * Ucitava ekstenzije sertifikata u skladisti ih u zadati certificateBuilder
     * @param certificateBuilder certificateBuilder u koji smestamo podatke
     */
    private void loadCertificateExtensions(X509v3CertificateBuilder certificateBuilder){
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


        //===================================================================================
        //========================== Popunjavanje koriscenja kljuca =========================
        //===================================================================================
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


        //===================================================================================
        //========================== Popunjavanje opstih ogranicenja ========================
        //===================================================================================
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

    }

    /**
     * Metoda koja generise sertifikat sa zadatim parom kljuceva
     * Informacije o sertifikatu se dohvataju iz GUI-a aplikacije
     * @param keyPair par kljuceva sertifikata
     * @return vraca izgenerisani i potpisani sertifikat
     */
    private X509Certificate generateCertificate(KeyPair keyPair){


        //===================================================================================
        //========================== Popunjavanje opstih podataka ===========================
        //===================================================================================

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

        // ucitavamo ekstenzije
        loadCertificateExtensions(certificateBuilder);

        //===================================================================================
        //============================ Potpisivanje sertifikata  ============================
        //===================================================================================

        try {
            ContentSigner signer = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm())
                    .build(keyPair.getPrivate());

            return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
        } catch (OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        }


        return null;
    }


    /**
     * Ucitava sve sertifikate/parove kljuceva koji su sacuvani u fajlu KEYSTORE_NAME
     * @return vraca nazive svih sertifikata/parova kljuceva u fajlu
     */
    @Override
    public Enumeration<String> loadLocalKeystore() {

        // tok za citanje iz fajla
        FileInputStream fis = null;

        try {
            // dohvatimo keystore
            keyStore =  KeyStore.getInstance(KEYSTORE_TYPE, BCProvider);

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

    /**
     * Isprazni sav sadrzaj keystore-a i novo stanje sacuva u fajl
     */
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

    /**
     * Metoda koja ucita sve informacije vezane za par kljuceva/ sertifikat i vraca da li je sertifikat potpisan ili ne
     * @param keyPairName naziv para kljuca/sertifikata koji prikazujemo
     * @return vraca 0 ako je sertifikat nepotpisan, 1 ako je potpisan od strane CA, 2 ako je u pitanju CA
     */
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

            Set<String> criticalExtensions = certificate.getCriticalExtensionOIDs();

            if (criticalExtensions == null)
                criticalExtensions = Collections.EMPTY_SET;



            //===================================================================================
            //========================== Oznacavanje kriticnih podataka =========================
            //===================================================================================
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



            //===================================================================================
            //========================== Ucitavanje koriscenja kljuca ===========================
            //===================================================================================
            boolean[] keyUsage = certificate.getKeyUsage();

            if (keyUsage != null)
                access.setKeyUsage(keyUsage);
            else if (keyUsageCritical)
                return KEYPAIR_ERROR_CODE;



            //===================================================================================
            //==========================      Ucitavanje SDA      ===============================
            //===================================================================================

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



            //===================================================================================
            //========================== Ucitavanje opstih ogranicenja ==========================
            //===================================================================================

            // dobijamo kolika je maksimalna duzina puta
            // duzina puta je jedino prisutna kod sertifikata koji su CA
            int basicConstraints = certificate.getBasicConstraints();

            // Ukoliko nije CA, vraca se vrednost -1,
            // postavimo odgovarajucu vrednost u gui
            if (basicConstraints != -1)
                access.setPathLen(basicConstraints == Integer.MAX_VALUE ? "" + basicConstraints : "");

            // namestamo odgovarajuce podatke na gui
            access.setCA(basicConstraints != -1);



            //===================================================================================
            //======================= Provera da li je potpisan/nepotpisan ======================
            //===================================================================================

            // verujemo da je trusted ukoliko je sertifikat/keypair CA
            if (basicConstraints != -1)
                return KEYPAIR_TRUSTED_CERT;



            // ako sertifikat nije potpisan od strane nekog CA
            // odnosno sam sebe je potpisao, smatramo ga nepotpisanim
            if (certificate.getSubjectDN().equals(certificate.getIssuerDN()))
                return KEYPAIR_UNSIGNED_CODE;


            // sertifikat je trusted ukoliko ga je potpisao neko
            // od lokalnih CA
            // izgleda da su samo CA trusted sertifikati, stoga ova provera nije potrebna
            // ali ostavicu ovaj kod ovde u slucaju da zatreba
            /*
            Enumeration<String> enumeration = keyStore.aliases();

            while(enumeration.hasMoreElements()){
                String key = enumeration.nextElement();

                if (key.equals(keyPairName))
                    continue;

                X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(key);

                try {
                    certificate.verify(x509Certificate.getPublicKey(), BCProvider);

                    //x509Certificate.verify(certificate.getPublicKey(), BCProvider);

                    return KEYPAIR_TRUSTED_CERT;
                } catch (CertificateException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {

                }

            }*/

            // sertifikat je potpisan od strane CA
            return KEYPAIR_SIGNED_CODE;
        } catch (KeyStoreException | IOException e) {
            e.printStackTrace();
        }

        // ovde dolazimo samo ako je doslo do neke greske
        return KEYPAIR_ERROR_CODE;
    }


    /**
     * Cuva unete informacije o sertifikatu/paru kljuceva i skladisti ih u keystore pod zadatim imenom
     * @param keyPairName naziv pod kojim cuvamo novogenerisani sertifikat/par kljuceva
     * @return true ako je operacija uspesno obavljena, false u slucaju da vec postoji zadati par kljuceva/sertifikat
     * sa tim imenom ili je doslo do neke greske
     */
    @Override
    public boolean saveKeypair(String keyPairName) {

        try {
            // ako vec postoji sertifikat/parKljuceva pod tim imenom
            if (keyStore.containsAlias(keyPairName))
                return false;

            // kreiramo instancu generatora kljuceva
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(access.getPublicKeyAlgorithm(), BCProvider);

            // inicijalizujemo generator kljuceva
            keyPairGenerator.initialize(Integer.parseInt(access.getPublicKeyParameter()));

            // generisemo par kljuceva
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // napravimo sertifikat
            X509Certificate x509Certificate = generateCertificate(keyPair);

            // sacuvamo sertifikat u keystore
            keyStore.setKeyEntry(keyPairName, keyPair.getPrivate(),
                    KEYSTORE_PASSWORD.toCharArray(),
                    new X509Certificate[]{x509Certificate});

            // sacuvamo novo stanje keystore-a u fajl
            saveKeyStore();

            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();

            GuiV3.reportError(e);
        }

        return false;
    }

    /**
     * Uklanja zadati par kljuceva/sertifikat iz keystore-a
     * @param keyPairName  naziv para kljuceva/sertifikata koji se brise
     * @return true ukoliko je operacija uspesna, false u suprotnom
     */
    @Override
    public boolean removeKeypair(String keyPairName) {

        try {
            // izbrisemo trazeni par kljuceva iz keystore-a
            keyStore.deleteEntry(keyPairName);

            // sacuvamo izmene
            saveKeyStore();

            // vratimo true jer je sve proslo normalno
            return true;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            GuiV3.reportError(e);
        }

        // ukoliko je doslo do neke greske pri brisanju iz keystore-a
        // vratimo false, odnosno da je doslo do greske
        return false;
    }


    /**
     * Ucitava iz zadatog fajla par kljuceva i cuva ga u keystore sa zadatim imenom
     * @param keyPairName naziv para kljuceva koji cemo da sacuvamo u keystore
     * @param keyStoreFilePath putanja do fajla para kljuceva
     * @param keyStorePassword sifra fajla para kljuceva
     * @return true ukoliko je operacija uspesna, false u suprotnom
     */
    @Override
    public boolean importKeypair(String keyPairName, String keyStoreFilePath, String keyStorePassword) {


        try(FileInputStream fis = new FileInputStream(keyStoreFilePath)){
            // ukoliko vec postoji par kljuceva/sertifikat sa zadatim imenom ispisati gresku i vratiti se
            if (keyStore.containsAlias(keyPairName)){
                GuiV3.reportError("Vec postoji par kljuceva/sertifikat sa zadatim imenom");
                return false;
            }

            // otvorimo udaljeni keystore
            KeyStore remoteKeyStore = KeyStore.getInstance(KEYSTORE_TYPE, new BouncyCastleProvider());

            // ucitamo sadrzaj udaljenog keystore-a
            remoteKeyStore.load(fis, keyStorePassword.toCharArray());

            // smatramo da se nalazi samo jedan par kljuceva u fajlu
            // stoga dohvatamo taj jedan i sacuvamo ga
            String alias = remoteKeyStore.aliases().nextElement();
            Key key = remoteKeyStore.getKey(alias, keyStorePassword.toCharArray());

            // sacuvamo entry
            keyStore.setKeyEntry(keyPairName, key, keyStorePassword.toCharArray(), remoteKeyStore.getCertificateChain(alias));

            // sacuvamo novo stanje keystore-a
            saveKeyStore();

            return true;
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Sacuva odabrani par kljuceva u zadati fajl sa zadatom sifrom
     * @param keyPairName naziv para kljuceva koji zelimo da sacuvamo u fajlu
     * @param filePath naziv/putanja fajla
     * @param password sifra fajla
     * @return true ukoliko je operacija uspesna, false u suprotnom
     */
    @Override
    public boolean exportKeypair(String keyPairName, String filePath, String password){

        try {
            KeyStore remoteKeyStore = KeyStore.getInstance(KEYSTORE_TYPE, BCProvider);

            // dohvatimo lanac sertifikata para kljuceva koje zelimo da eksportujemo
            Certificate[] chain = keyStore.getCertificateChain(keyPairName);

            // alociramo keystore
            remoteKeyStore.load(null, null);

            // ubacimo u novi keystore
            remoteKeyStore.setKeyEntry(keyPairName,
                    keyStore.getKey(keyPairName, KEYSTORE_PASSWORD.toCharArray()),
                    password.toCharArray(),
                    chain
            );

            // sacuvamo u zadati fajl
            saveKeyStore(remoteKeyStore, filePath, password);

            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
            GuiV3.reportError(e);
        }
        // vracamo false ukoliko je doslo do neke greske
        return false;
    }


    /**
     *
     * @param filePath putanja do fajla u kojem se nalazi sertifikat
     * @param certificateName naziv pod kojim zelimo da sacuvamo sertifikat u keystore
     * @return true ako je operacija uspesna, false u suprotnom
     */
    @Override
    public boolean importCertificate(String filePath, String certificateName) {

        try(FileInputStream fis = new FileInputStream(filePath)){

            // proverimo da li vec postoji, ako postoji vratimo false
            if (keyStore.containsAlias(certificateName)){
                GuiV3.reportError("Vec postoji sertifikat/par kljuceva sa zadatim imenom");

                return false;
            }
            // izgenerisemo sertifikat
            X509Certificate importedCertificate = (X509Certificate) CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(fis);


            keyStore.setCertificateEntry(certificateName, importedCertificate );

            saveKeyStore();

            return true;
        } catch (IOException | CertificateException | KeyStoreException e) {
            e.printStackTrace();
            GuiV3.reportError(e);
        }

        return false;
    }

    /**
     *
     * @param file naziv/putanja fajla gde zelimo da eksportujemo sertifikat
     * @param certificateName naziv sertifikata koji eksportujemo
     * @param encoding format fajla moze biti DER ili PEM
     * @param format da li treba ukljuciti lanac ili ne
     * @return true ako je operacija uspesno obavljena, false u suprotnom
     */
    @Override
    public boolean exportCertificate(String file, String certificateName, int encoding, int format) {

        try(FileOutputStream fos = new FileOutputStream(file)){

            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(certificateName);


            if (encoding == Constants.DER){
                fos.write(certificate.getEncoded());

                return true;
            }

            // sigurno treba da sacuvamo fajl kao PEM

            OutputStreamWriter osw = new OutputStreamWriter(fos);
            JcaPEMWriter pemWriter = new JcaPEMWriter(osw);

            // prvi upisemo sam sertifikat
            pemWriter.writeObject(certificate);

            // ako treba ceo lanac
            if (format == Constants.CHAIN){
                Certificate[] certificates = keyStore.getCertificateChain(certificateName);

                if (certificates != null)
                    for(Certificate chainCertificate : certificates)
                        pemWriter.writeObject(chainCertificate);
            }

            // zatvorimo strimove
            pemWriter.close();
            osw.close();

            return true;
        } catch (IOException | KeyStoreException | CertificateEncodingException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Generise CSR za zadati sertifikat i cuva zahtev u fajlu zadatog naziva
     * @param fileName putanja do fajla u koji zelimo da sacuvamo
     * @param certificateName naziv sertifikata koji zelimo da potpisemo
     * @param algorithm algoritam kojim enkriptujemo zahtev za potpis sertificata
     * @return true ako je operacija uspesno obavljena, false u suprotnom
     */
    @Override
    public boolean exportCSR(String fileName, String certificateName, String algorithm) {
        try(FileWriter fileWriter = new FileWriter(fileName)){
            // sertifikat za koji hocemo da generisemo zahtev za potpisivanje
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(certificateName);

            // builder za CSR
            JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    certificate.getSubjectX500Principal(),
                    certificate.getPublicKey()
            );

            // kojim algoritmom potpisujemo zahtev
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(algorithm).setProvider(BCProvider);

            // privatni kljuc kojim cemo potpisati zahtev
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(certificateName, KEYSTORE_PASSWORD.toCharArray());

            // potpisivac zahteva
            ContentSigner signer = csBuilder.build(privateKey);

            // zahtev za potpisivanje
            PKCS10CertificationRequest csr = p10Builder.build(signer);

            // ispisujemo u pem formatu
            JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);

            // upisujemo u fajl
            pemWriter.writeObject(csr);

            // zatvaramo tok
            pemWriter.close();

            // vratimo uspesnot operacije
            return true;
        } catch (IOException | KeyStoreException | UnrecoverableKeyException | OperatorCreationException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Importuje CSR u keystore i vraca opste informacije o subjektu CSR-a
     * @param fileName putanja do fajla
     * @return opste informacije o subjektu iz CSR-a
     */
    @Override
    public String importCSR(String fileName) {

        try(FileReader pemReader = new FileReader(fileName)){
            PEMParser pemParser = new PEMParser(pemReader);

            // procitamo sertifikat
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();

            // zapamtimo trenutni csr
            this.csr = csr;

            // vratimo podatke o podnosiocu zahteva formatirano po postavci zadatka
            return reformatBasicCertInfo(csr.getSubject().toString());

        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    @Override
    public boolean signCSR(String file, String certificateIssuerName, String algorithm) {

        try(FileOutputStream fos = new FileOutputStream(file)){


            if (access.getVersion() != VERSION_3_CODE){
                GuiV3.reportError("Podrzani su samo sertifikati verzije 3");
                return false;
            }

            //============================================ SERTIFIKAT ZA POTPISIVANJE======================================
            // Popunjavamo sertifikat podacima

            PublicKey csrPublicKey = new JcaPKCS10CertificationRequest(this.csr).setProvider(BCProvider).getPublicKey();

            X500Name issuerName = new JcaX509CertificateHolder((X509Certificate) keyStore.getCertificate(certificateIssuerName)).getSubject();

            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuerName,
                    new BigInteger(access.getSerialNumber()),
                    access.getNotBefore(),
                    access.getNotAfter(),
                    this.csr.getSubject(),
                    csrPublicKey
            );

            // ucitamo ekstenzije sertifikata
            loadCertificateExtensions(certificateBuilder);
            //==============================================================================================================

            // potpis
            ContentSigner signer = new JcaContentSignerBuilder(algorithm)
                    .setProvider(BCProvider)
                            .build((PrivateKey) keyStore.getKey(certificateIssuerName, KEYSTORE_PASSWORD.toCharArray()));

            // izgradmo sertifikat za potpisivanje
            X509Certificate signedCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));

            // nekoliko klasa zarad popunjavanja fajla formata PKCS7
            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();

            // lista sertifikata u lancu
            List<JcaX509CertificateHolder> certificateChain = new ArrayList<>();

            CMSTypedData cmsTypedData = new CMSProcessableByteArray(signedCertificate.getEncoded());

            // dodamo prvo potpisani sertifikat u lanac
            certificateChain.add(new JcaX509CertificateHolder(signedCertificate));

            // dodamo onda ostale iz lanca sertifikata koji potpisuje
            for(Certificate certificate :  keyStore.getCertificateChain(certificateIssuerName))
                certificateChain.add(new JcaX509CertificateHolder((X509Certificate) certificate));

            cmsSignedDataGenerator.addCertificates(new CollectionStore(certificateChain));

            CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData);

            fos.write(cmsSignedData.getEncoded());

            return true;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | InvalidKeyException | UnrecoverableKeyException | OperatorCreationException | CertificateException | CMSException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Ucitava CA Reply za zadati sertifikat
     * @param file naziv fajla gde se nalazi CA reply
     * @param certificateName  naziv sertifikata za kojeg ucitavamo CA Reply
     * @return true ako je uspesno, false u suprotnom
     */
    @Override
    public boolean importCAReply(String file, String certificateName) {

        try (FileInputStream fis = new FileInputStream(file)) {
            // format je CMS/PKCS7
            CMSSignedData signature = new CMSSignedData(fis);

            // vid za dohvatanja sertifikata
            Store<X509CertificateHolder> store = signature.getCertificates();

            Collection<X509CertificateHolder> certificateHolders = store.getMatches(null);

            X509Certificate[] certificateChain = new X509Certificate[certificateHolders.size()];

            // samo da znamo gde upisujemo sertifikat
            int i = 0;

            // iteriramo kroz lanac i dohvatamo sve sertifikate u lancu
            for (X509CertificateHolder holder : certificateHolders)
                certificateChain[i++] = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);

            // privatni kljuc za koji je sertifikat vezan
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(certificateName, KEYSTORE_PASSWORD.toCharArray());

            // sacuvamo izmene
            keyStore.setKeyEntry(certificateName, privateKey, KEYSTORE_PASSWORD.toCharArray(), certificateChain);

            saveKeyStore();

            return true;
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | CMSException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Funkcija koja proverava da li sertifikat sa zadatim imenom sme da potpisuje Certificate Sign Request
     * @param certificateName naziv sertifikata
     * @return true ako sme da potpise CSR, false u suprotnom ili u slucaju greske
     */
    @Override
    public boolean canSign(String certificateName) {

        try {
            // verovatno treba dohvatati i key usage i videti za sta se koristi
            // moze da potpise samo ukoliko je CA
            return ((X509Certificate)keyStore.getCertificate(certificateName)).getBasicConstraints() != -1;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public String getSubjectInfo(String certificateName) {


        try {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(certificateName);

            String subjectInfo = certificate.getSubjectDN().toString();

            // vracamo koji mu je signature algoritam uz osnovne podatke
            return reformatBasicCertInfo(subjectInfo + ",SA=" + certificate.getSigAlgName());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Dohvata naziv algoritma javnog kljuca zadatog sertifikata
     * @param certificateName naziv sertifikata
     * @return naziv algoritma
     */
    @Override
    public String getCertPublicKeyAlgorithm(String certificateName) {

        try {
            // vratimo algoritam javnog kljuca sertifikata
            return keyStore.getCertificate(certificateName).getPublicKey().getAlgorithm();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *  Vraca parametar javnog kljuca sertifikata
     * @param certificateName naziv sertifikata
     * @return parametar javnog kljuca
     */
    @Override
    public String getCertPublicKeyParameter(String certificateName) {

        try {
            // dohvatimo javni kljuc sertifikata
            PublicKey publicKey = keyStore.getCertificate(certificateName).getPublicKey();

            // proverimo koji je algoritam u pitanju i vratiom duzinu kljuca
            if (publicKey instanceof DSAPublicKey)
                return ((DSAPublicKey) publicKey).getY().bitLength() + "";
            else if (publicKey instanceof RSAPublicKey)
                return ((RSAPublicKey) publicKey).getModulus().bitLength() + "";
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }
}
