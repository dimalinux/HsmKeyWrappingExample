package to.noc.hsm.lunasa.example;

import com.safenetinc.luna.LunaSlotManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

/*
 *  This class looks for a file named "partition.properties" in the current
 *  user's home directory.  The file needs the following two properties:
 *
 *    partitionName = YourPartitionName
 *    partitionPass = PasswordForYourTestPartition
 *
 */
public class HsmManager {
    private static final LunaSlotManager slotManager;
    private static KeyStore keyStore;
    private static final String partitionName;
    private static final String partitionPass;
    
    static {
        Security.addProvider(new com.safenetinc.luna.provider.LunaProvider());
        slotManager = LunaSlotManager.getInstance();

        Properties prop = new Properties();
        try {
            File propFile = new File(System.getProperty("user.home"), "partition.properties");
            InputStream in = new FileInputStream(propFile);
            prop.load(in);
            in.close();
        } catch (IOException ex) {
            ex.printStackTrace();
            System.exit(-1);
        }

        partitionName = prop.getProperty("partitionName");
        partitionPass = prop.getProperty("partitionPass");
        
        if (partitionName == null || partitionPass == null) {
            System.err.println("Aborting, mandatory properties not set");
            System.exit(-1);
        }
    }

    public static void login() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        slotManager.login(partitionName, partitionPass);
        keyStore = KeyStore.getInstance("Luna");
        keyStore.load(null, null);
    }

    public static void logout() {
        slotManager.logout();
        keyStore = null;
    }
    
    public static boolean hasSavedKey(String alias) throws KeyStoreException {
        // I think the second check alone is sufficient
        return keyStore.containsAlias(alias) && keyStore.isKeyEntry(alias);
    }
    
    public static Key getSavedKey(String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        return keyStore.getKey(alias, null);
    }
    
    public static void saveKey(String alias, Key key) throws KeyStoreException {
        keyStore.setKeyEntry(alias, key, null, null);
    }

    public static void saveRsaKey(String alias, Key key, Certificate[] chain) throws KeyStoreException {
        keyStore.setKeyEntry(alias, key, null, chain);
    }
    
    public static void deleteKey(String alias) throws KeyStoreException {
        keyStore.deleteEntry(alias);
    }

    public static void setSecretKeysExtractable(boolean isExtractable) {
        slotManager.setSecretKeysExtractable(isExtractable);
    }
    
}
