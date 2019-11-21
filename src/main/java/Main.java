
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;



public class Main {
    public static void main(String[] args) throws Exception {

        byte[] dataxifrat;
        byte[] datadesxifrat;
        String data;

        System.out.println("Exercicis 1.1");
        KeyPair keyPair;
        keyPair = Claus.randomGenerate(1024);
        System.out.println("datos:  ");
        data = new Scanner(System.in).nextLine();
        dataxifrat = Claus.encryptData(data.getBytes(),keyPair.getPublic());
        System.out.println("data xifrat: "+new String(dataxifrat));
        datadesxifrat = Claus.decryptData(dataxifrat,keyPair.getPrivate());
        System.out.println("data desxifrat: "+new String(datadesxifrat));
        System.out.format("claus Publico: %s "+"\n"+" claus Privat: %s",keyPair.getPublic(),keyPair.getPrivate());


        System.out.println("\n\n\nExercicis 1.2");

        KeyStore keyStore = Claus.loadKeyStore("/home/dam2a/.keystore.jks","112123");
        System.out.println("Tipo: "+keyStore.getType());
        System.out.println("tamaño: "+keyStore.size());
        Enumeration<String> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements()){
            System.out.println("Alias del keystore: " + enumeration.nextElement());
        }
        System.out.println("Certificado: " + keyStore.getCertificate("jordi"));

        System.out.println("Exercicis 1.2.2");
        SecretKey secretKey = Claus.keygenKeyGeneration(128);

        // get user password and file input stream
        String pas = "112123";
        char[] password = pas.toCharArray();

        try (FileInputStream fis = new FileInputStream("/home/dam2a/.keystore.jks")) {
            keyStore.load(fis, password);
        }

        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);

        // save my secret key
        javax.crypto.SecretKey mySecretKey;
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry("secretKeyAlias", skEntry, protParam);

        // store away the keystore
        try (FileOutputStream fos = new FileOutputStream("/home/dam2a/.keystore.jks")) {
            keyStore.store(fos, password);
        }


//        System.out.println("Exercicis 1.3");
//        FileInputStream fis = new FileInputStream("/home/dam2a/jordi.cer");
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        Collection c = cf.generateCertificates(fis);
//        Iterator i = c.iterator();
//        while (i.hasNext()) {
//            Certificate cert = (Certificate)i.next();
//            System.out.println(cert);
//        }


        System.out.println("\n\n\nExercicis 1.4");

        FileInputStream is = new FileInputStream("/home/dam2a/.keystore");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "112123".toCharArray());

        String alias = "mykey";

        Key key = keystore.getKey(alias, "112123".toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();
            System.out.println(publicKey.toString());
        }

        System.out.println("\n\n\nExercicis 1.5");

        byte[] dataBy = "qweqwe".getBytes();
        PrivateKey privKey = keyPair.getPrivate();
        byte[] firma = Claus.signData(dataBy,privKey);
        System.out.println(new String(firma));

        System.out.println("\n\n\nExercicis 1.6");
        PublicKey publicKey = keyPair.getPublic();
        boolean verificado = Claus.validateSignature(dataBy,firma,publicKey);
        System.out.println(verificado);

        System.out.println("\n\n\nExercicis 2");

        KeyPair claves = Claus.randomGenerate(1024);

        PublicKey pubKey = claves.getPublic();
        PrivateKey privateKey = claves.getPrivate();

        byte[][] clauEmbEnc = Claus.encryptWrappedData(dataBy,pubKey);


        byte[]  clauEmbDec = Claus.decryptWrappedData(clauEmbEnc,privateKey);
        System.out.println(new String(clauEmbDec));
    }
}

