package to.noc.hsm.lunasa.example;

import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.key.LunaSecretKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import static java.lang.System.out;

/*
 *  Example of how to use encrypted host keys with the cryptographic provider for the
 *  Luna SA HSM.  This code was tested with firmware 5.3.5.  5.1.2, the original
 *  version we started with, allowed key extraction of keys unwrapped on the HSM.
 *  Use a 5.3 version if you want to use encrypted host keys!
 *
 *  Example output:
 *   HSM KEK ID (a handle, not in clear):
 *   	0x0000000000000030
 *   Original unwrapped 3DES Key (in the clear):
 *   	0xFD100BC7E5DA769E2F7083AE5DF7E02FDCC13445C162077A
 *   KEK wrapped 3DES key (host key):
 *   	0x1BA43DE7C5A6D63787C37034A6B2F20626594FCC59F236E12DC0A9110EB43D42
 *
 *   Stopping and starting session with HSM.
 *   Pretend that the host key was stored and restored from a database while disconnected
 *
 *   Unwrapped 3DES key is a reference to the HSM key (i.e. not in clear):
 *   	0x0000000000000034
 *   Class of unwrapped key: com.safenetinc.luna.provider.key.LunaSecretKey
 *   Original plaintext:
 *   	12345678
 *   Unwrapped (on the HSM) key was not available for local use (desired).
 *   LunaProvider encrypt result in hex:
 *   	0xC7403FC98BEEC004
 *   LunaProvider decrypt result:
 *   	12345678
 */
public class KeyWrappingExample {
    //
    // Alias used to store the the KEK (Key Encryption Key) on the HSM
    //
    private static final String KEK_ALIAS = "KEK_AES_TEST";

    //  OpenJDK handles AES 256 just fine, but I had to lower this to 128 for
    //  Oracle's off-the-shelf JDK which has strong crypto disabled.
    private static int KEK_NUM_KEY_BITS = 128;

    //
    //  AES has a block size of 128 bits or 16 bytes.  Used easy HEX values so you can plug them
    //  into a website like http://aes.online-domain-tools.com/ to verify encrypted values.
    //
    private static final byte[] FIXED_128BIT_IV_FOR_TESTS =
            LunaUtils.hexStringToByteArray("DEADD00D8BADF00DDEADBABED15EA5ED");


    public static void main(String[] args) throws Exception {
        final String hostKeyType = "DESede";

        HsmManager.login();
        //HsmManager.setSecretKeysExtractable(false);

        SecretKey kek = createNewHsmKek();
        out.println("HSM KEK ID (a handle, not in clear):\n\t" + getHex(kek.getEncoded()));

        SecretKey des3Key = createSoftwareKey(hostKeyType);
        out.println("Original unwrapped 3DES Key (in the clear):\n\t" + getHex(des3Key.getEncoded()));

        byte[] wrappedHostKey = wrapKeyWithKek(kek, des3Key);
        out.println("KEK wrapped 3DES key (host key):\n\t" + getHex(wrappedHostKey));


        out.println("\nStopping and starting session with HSM.");
        HsmManager.logout();
        out.println("Pretend that the host key was stored and restored from a database while disconnected\n");
        kek = null;
        des3Key = null;
        HsmManager.login();

        kek = getExistingHsmKek();
        SecretKey unwrapped3DesKey = unwrapKeyWithKek(kek, hostKeyType, wrappedHostKey);
        out.println("Unwrapped 3DES key is a reference to the HSM key (i.e. not in clear):\n\t" + getHex(unwrapped3DesKey.getEncoded()));
        out.println("Class of unwrapped key: " + unwrapped3DesKey.getClass().getCanonicalName());


        String plainText = "12345678";
        out.println("Original plaintext:\n\t" + plainText);

        try {
            // Prove that the unwrapped (on the HSM) key can not be used locally.  With the broken
            // Luna SA 5.1.2 firmware this was possible, but with 5.3.5 we are correctly triggering
            // an exception.
            Cipher sunJceCipher = Cipher.getInstance("DESede/ECB/NoPadding", "SunJCE");
            sunJceCipher.init(Cipher.ENCRYPT_MODE, unwrapped3DesKey);
            out.println("ERROR:  This line should have been skipped by an invalid key exception.");
        } catch (InvalidKeyException e) {
            out.println("Unwrapped (on the HSM) key was not available for local use (desired).");
        }

        //  Start Luna HSM cipher operation
        Cipher lunaHsmCipher = Cipher.getInstance("DESede/ECB/NoPadding", "LunaProvider");

        lunaHsmCipher.init(Cipher.ENCRYPT_MODE, unwrapped3DesKey);
        byte[] cipherText = lunaHsmCipher.doFinal(plainText.getBytes());
        out.println("LunaProvider encrypt result in hex:\n\t" + getHex(cipherText));

        lunaHsmCipher.init(Cipher.DECRYPT_MODE, unwrapped3DesKey);
        byte[] originalClearText = lunaHsmCipher.doFinal(cipherText);
        out.println("LunaProvider decrypt result:\n\t" + new String(originalClearText));

        /*
           TBD:  See if we can get around the system my unwrapping the key using crypto
                 operations.

        Cipher wrappingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("IV", "LunaProvider");
        algParams.init(new IvParameterSpec(FIXED_128BIT_IV_FOR_TESTS));
        wrappingCipher.init(Cipher.DECRYPT_MODE, kek, algParams);
        byte[] unwrapped3DesKeyInClear = lunaHsmCipher.doFinal(wrappedHostKey);
        out.println("Sneaky unwrap result:\n\t" + getHex(unwrapped3DesKeyInClear));
        */

        HsmManager.logout();
    }


    //
    //  KEK is generated on HSM.  We never know its value, just it's alias to
    //  access it.
    //
    private static SecretKey createNewHsmKek()  throws GeneralSecurityException {

        if (HsmManager.hasSavedKey(KEK_ALIAS)) {
            HsmManager.deleteKey(KEK_ALIAS);
        }

        KeyGenerator kg = KeyGenerator.getInstance("AES", "LunaProvider");
        kg.init(KEK_NUM_KEY_BITS);

        LunaSecretKey kek = (LunaSecretKey) kg.generateKey();

        //
        //  The Safenet sales engineer suggested we set the values below on a
        //  KEK.  It doesn't work though.  Disabling CKA_ENCRYPT disables wrap()
        //  operations and disabling CKA_DECRYPT disables unwrap() operations.
        //
        //LunaTokenObject obj = LunaTokenObject.LocateObjectByHandle(kek.GetKeyHandle());
        //obj.SetBooleanAttribute(LunaAPI.CKA_ENCRYPT, false);
        //obj.SetBooleanAttribute(LunaAPI.CKA_DECRYPT, false);

        HsmManager.saveKey(KEK_ALIAS, kek);

        return kek;
    }


    private static SecretKey getExistingHsmKek() throws GeneralSecurityException {
        // casting KEY -> SecretKey
        return (SecretKey) HsmManager.getSavedKey(KEK_ALIAS);
    }

    //
    //  Create software-only (not stored on HSM) key
    //
    private static SecretKey createSoftwareKey(String keyType) throws GeneralSecurityException {
        //
        // SunJCE would be used by default when running openjdk 1.7, but I decided
        // to be explicit to ensure we are generating a key in software for this
        // example.
        //
        KeyGenerator generator = KeyGenerator.getInstance(keyType, "SunJCE");
        generator.init(new SecureRandom());
        return generator.generateKey();
    }

    //
    // Wrap the passed in key with the KEK on the HSM
    //
    private static byte[] wrapKeyWithKek(SecretKey hsmKek, SecretKey softwareKey) throws GeneralSecurityException {
        Cipher wrappingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("IV", "LunaProvider");
        algParams.init(new IvParameterSpec(FIXED_128BIT_IV_FOR_TESTS));
        wrappingCipher.init(Cipher.WRAP_MODE, hsmKek, algParams);
        return  wrappingCipher.wrap(softwareKey);
    }

    //
    //  Unwrap the passed in key with the KEK on the HSM
    //
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


