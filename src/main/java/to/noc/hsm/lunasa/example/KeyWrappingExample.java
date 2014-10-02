package to.noc.hsm.lunasa.example;

import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.key.LunaSecretKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static java.lang.System.out;

/*
 *  Example of how to use encrypted host keys with the Luna SA cryptographic provider.
 *  Unfortunately, this example also shows that the AWS CloudHSM device is not protecting
 *  keys that were unwrapped on the HSM from extraction.  An attacker gaining access to
 *  both your database (with encrypted host keys) and access to your HSM client host can
 *  easily and quickly convert all encrypted host keys into their unencrypted form.
 *
 *  Sample output from the code below:
 *
 *   HSM KEK ID (a handle, not in clear):
 *       0x0000000000000011
 *
 *   Software-Only 3DES Key (in the clear):
 *       0x835B7534DC266DA22646E3DF3D5D7A6B4A348FCB2F67DA76
 *
 *   KEK wrapped 3DES key (host key):
 *       0x511382325E89988B500DA3F9DFF5A53CCECF63B445A68450F426EC83464493E4
 *
 *   Stopping and starting session with HSM.
 *   Pretend that the host key was stored and restored from a database while disconnected
 *
 *   Unwrapped 3DES key is same as original (in clear):
 *       0x835B7534DC266DA22646E3DF3D5D7A6B4A348FCB2F67DA76
 *
 *   Class of unwrapped key: com.safenetinc.luna.provider.key.LunaSecretKey
 *
 *   Original plaintext:
 *       12345678
 *
 *   SunJCE encryption result:
 *       0x11559F95F6E862AF
 *
 *   LunaProvider HSM decrypt result:
 *       12345678
*/
public class KeyWrappingExample {
    //
    // Alias used to store the the KEK (Key Encryption Key) on the HSM
    //
    private static final String KEK_ALIAS = "KEK_AES_TEST";

    //  OpenJDK handles AES 256 just fine, but if you're using Oracle's JDK, it
    //  may have strong crypto disabled requiring you to drop the key size below
    //  down to 128.
    private static int KEK_NUM_KEY_BITS = 256;

    //
    //  AES-* has a block size of 128 bits or 16 bytes.  Used easy HEX values so you can plug them
    //  into a website like http://aes.online-domain-tools.com/ to verify encrypted values.
    //
    private static final byte[] FIXED_128BIT_IV_FOR_TESTS =
            LunaUtils.hexStringToByteArray("DEADD00D8BADF00DDEADBABED15EA5ED");



    public static void main(String[] args) throws Exception {
        final String hostKeyType = "DESede";

        HsmManager.login();
        HsmManager.setSecretKeysExtractable(false);

        SecretKey kek = createNewHsmKek();
        out.println("HSM KEK ID (a handle, not in clear):\n\t" + getHex(kek.getEncoded()));

        SecretKey des3Key = createSoftwareKey(hostKeyType);
        out.println("Software-Only 3DES Key (in the clear):\n\t" + getHex(des3Key.getEncoded()));

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
        out.println("Unwrapped 3DES key is same as original (in clear):\n\t" + getHex(unwrapped3DesKey.getEncoded()));
        out.println("Class of unwrapped key: " + unwrapped3DesKey.getClass().getCanonicalName());

        //
        //  Give an example using using the unwrapped LunaSecretKey in both a software
        //  cipher operation and an HSM cipher operation.  If the LunaSecretKey was
        //  protected in hardware, the SunJCE operation with it would fail.
        //
        String plainText = "12345678";
        byte[] plainTextBytes = plainText.getBytes();
        out.println("Original plaintext:\n\t" + plainText);

        //  Start software cipher operation
        Cipher sunJceCipher = Cipher.getInstance("DESede/ECB/NoPadding", "SunJCE");
        sunJceCipher.init(Cipher.ENCRYPT_MODE, unwrapped3DesKey);
        byte[] cipherText = sunJceCipher.doFinal(plainText.getBytes());
        out.println("SunJCE encryption result:\n\t" + getHex(cipherText));

        //  Start Luna HSM cipher operation
        Cipher lunaHsmCipher = Cipher.getInstance("DESede/ECB/NoPadding", "LunaProvider");
        lunaHsmCipher.init(Cipher.DECRYPT_MODE, unwrapped3DesKey);
        byte[] originalClearText = lunaHsmCipher.doFinal(cipherText);
        out.println("LunaProvider HSM decrypt result:\n\t" + new String(originalClearText));


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
        //  Since our KEK will only be used for wrap and unwrap operations, we should
        //  disable encryption and decryption operations.
        //
        //  Note:  In theory, the commented out lines below will work on Luna SA
        //         firmwares 5.2 and above, but on our AWS CloudHSM firmware disabling
        //         encrypt and decrypt functionality will disable Cipher.WRAP_MODE
        //         and Cipher.UNWRAP_MODE respectively.  This is makes sense.
        //         If the unwrapped keys are not stored and protected on the HSM,
        //         wrapping and unwrapping operations *are* providing somewhat general
        //         encrypt and decrypt functionality.
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


