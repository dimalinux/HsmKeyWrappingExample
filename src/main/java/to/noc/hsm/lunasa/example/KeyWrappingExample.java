package to.noc.hsm.lunasa.example;

import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.key.LunaSecretKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.PrintStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyWrappingExample {
    // Alias used to store the the KEK (Key Encryption Key) on the HSM
    private static final String KEK_ALIAS = "MASTER_KEK";

    private static byte[] FIXED_128BIT_IV_FOR_TESTS = {
            (byte) 65, (byte) 66, (byte) 67, (byte) 68, (byte) 69, (byte) 70, (byte) 71, (byte) 72,
            (byte) 73, (byte) 74, (byte) 75, (byte) 76, (byte) 77, (byte) 78, (byte) 79, (byte) 80
    };


    public static void main(String[] args) throws Exception {
        final String hostKeyType = "DES";
        final PrintStream out = System.out;

        HsmManager.login();

        SecretKey kek = createNewHsmKek();
        out.println("HSM KEK ID: " + getHex(kek.getEncoded()));

        SecretKey desKey = createSoftwareKey(hostKeyType);
        out.println("Software-Only DES Key: " + getHex(desKey.getEncoded()));

        byte[] wrappedHostKey = wrapKeyWithKek(kek, desKey);
        out.println("KEK wrapped DES key (host key): " + getHex(wrappedHostKey));


        out.println("Logged out of HSM... pretend that wrapped key was stored to a database.");
        HsmManager.logout();
        kek = null;
        desKey = null;

        out.println("Pretend time has passed, the host key was was loaded from a DB, starting new HSM session");
        HsmManager.login();

        kek = getExistingHsmKek();
        SecretKey unwrapedDesKey = unwrapKeyWithKek(kek, hostKeyType, wrappedHostKey);
        out.println("Unwrapped DES key is same as original: " + getHex(unwrapedDesKey.getEncoded()));


        /*
         *  Now that we have the key unwrapped, we can use it to decrypt or encrypt in software.
         *  The SafeNet representative pointed out that we can temporarily inject the key into
         *  the HSM to operate on data, but doing so doesn't give us any additional security,
         *  since it was the key itself that we are trying to protect.  Our applets are only
         *  alive for seconds.  Injecting the key into the HSM will not reduce the length of
         *  time the unprotected key is in memory.
         */

        //  ==== Start software only encryption operation ====
        long start = System.currentTimeMillis();
        byte[] plainText = "12345678".getBytes();
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, unwrapedDesKey);
        byte[] cipherText = cipher.doFinal(plainText);
        long elapsedMs = System.currentTimeMillis() - start;
        out.println("Software encryption result (" + elapsedMs + "ms): " + getHex(cipherText));
        //  ==== End software only encryption operation ====


        //  ==== Start HSM encryption operation ====
        start = System.currentTimeMillis();
        LunaSecretKey hsmInjectedDesKey = LunaSecretKey.InjectSecretKey(unwrapedDesKey);
        // Key is on HSM, but won't exist past this session unless we call this method:
        //    hsmInjectedDesKey.MakePersistent("some key alias");
        unwrapedDesKey = null;

        Cipher hsmCipher = Cipher.getInstance("DES/ECB/NoPadding", "LunaProvider");
        hsmCipher.init(Cipher.ENCRYPT_MODE, hsmInjectedDesKey);
        byte[] hsmCipherText = hsmCipher.doFinal(plainText);
        elapsedMs = System.currentTimeMillis() - start;
        out.println("HSM encryption result (" + elapsedMs + "ms): " + getHex(hsmCipherText));
        //  ==== End HSM encryption operation ====

        //
        //  You can cross-check the correctness of the encryption values using this website:
        //     http://des.online-domain-tools.com/
        //

        HsmManager.logout();
    }


    //  KEK is generated on HSM.  We never know its value, just it's alias name.
    private static SecretKey createNewHsmKek()  throws GeneralSecurityException {
        SecretKey kek;

        if (HsmManager.hasSavedKey(KEK_ALIAS)) {
            HsmManager.deleteKey(KEK_ALIAS);
        }

        KeyGenerator kg = KeyGenerator.getInstance("AES", "LunaProvider");
        kg.init(256);
        kek = kg.generateKey();
        HsmManager.saveKey(KEK_ALIAS, kek);

        return kek;
    }


    private static SecretKey getExistingHsmKek() throws GeneralSecurityException {
        // casting KEY -> SecretKey
        return (SecretKey) HsmManager.getSavedKey(KEK_ALIAS);
    }


    // create software-only (not stored on HSM) key
    private static SecretKey createSoftwareKey(String keyType) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(keyType);
        generator.init(new SecureRandom());
        return generator.generateKey();
    }


    // wrapping operation is performed on the HSM
    private static byte[] wrapKeyWithKek(SecretKey hsmKek, SecretKey softwareKey) throws GeneralSecurityException {
        Cipher wrappingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("IV", "LunaProvider");
        algParams.init(new IvParameterSpec(FIXED_128BIT_IV_FOR_TESTS));
        wrappingCipher.init(Cipher.WRAP_MODE, hsmKek, algParams);
        return  wrappingCipher.wrap(softwareKey);
    }


    private static SecretKey unwrapKeyWithKek(SecretKey hsmKey, String keyAlgorithm, byte[] wrappedKeyBytes) throws GeneralSecurityException {
        Cipher wrappingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("IV", "LunaProvider");
        algParams.init(new IvParameterSpec(FIXED_128BIT_IV_FOR_TESTS));
        wrappingCipher.init(Cipher.UNWRAP_MODE, hsmKey, algParams);
        return  (SecretKey) wrappingCipher.unwrap(wrappedKeyBytes, keyAlgorithm, Cipher.SECRET_KEY);
    }


    private static String getHex(byte array[]) {
        return "0x" + LunaUtils.getHexString(array, false).toUpperCase();
    }
}


