package to.noc.hsm.lunasa.example;

import com.google.common.primitives.Bytes;
import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.key.LunaSecretKey;
import org.apache.commons.lang3.SerializationUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.Serializable;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static java.lang.System.out;


/*
 *   In some cases we may want use Java serialization with encrypted (by the Luna SA HSM)
 *   host keys.  This is a simple example of one way it might be done.
 *
 *   Example output:
 *
 *   HSM KEK (not in the clear):
 *       0x0000000000000010
 *
 *   Initial Host Key (in the clear):
 *        0x5B756ED09B98F87A58790BB34A989143E5F7431FF41694D6
 *
 *   Wrapping IV for Host Key:
 *        0x5B756ED09B98F87A58790BB34A989143E5F7431FF41694D6
 *
 *   KEK Wrapped Host Key:
 *        0x12AED07A056ECF19F53D096FAAEE07D3350FA7725883F8EEE194A3D19FC88CF6
 *
 *   Serialized Key Holder:
 *       0xACED000573720047746F2E6E6F632E68736D2E6C756E6173612E6578616D706C652E57726...
 *
 *   Index of IV in Serialized Data:
 *       227
 *
 *   Index of Encrypted Key in Serialized Data:
 *       185
 *
 *   Index of Unencrypted Key in Serialized Data:
 *       -1
 *
 *   Deserialized and Unwrapped Host Key (same as original):
 *       0x5B756ED09B98F87A58790BB34A989143E5F7431FF41694D6
 *
 *   Plain Text:
 *       0xDEADD00D8BADF00DDEADBABED15EA5ED
 *
 *   Cipher Text:
 *       0x08583359848B684086F83C66CFBD486D
 *
 *   Plain Text Decrypted:
 *       0xDEADD00D8BADF00DDEADBABED15EA5ED
 */
public class WrappedKeySerialization {

    // Label used to store the the KEK (Key Encryption Key) on the HSM
    private static final String KEK_ALIAS = "KEK_3DES";


    /*
     *  Provides a serializable wrapper around the encrypted host key.  Key will automatically
     *  be unwrapped the first time it is used after deserialization.
     */
    private static class SerializableKeyHolder implements Serializable {

        // Transient objects are not serialized and are null after deserialization
        transient private SecretKey secretKey;

        private byte[] encryptedHostKey;
        private byte[] iv;
        private String keyAlgorithm;


        private SerializableKeyHolder(String keyAlgorithm, byte[] iv, byte[] encryptedHostKey) {
            this.keyAlgorithm = keyAlgorithm;
            this.iv = iv;
            this.encryptedHostKey = encryptedHostKey;
        }

        public SecretKey getSecretKey() throws GeneralSecurityException {
            if (secretKey == null) {
                secretKey = unwrapKeyWithKek(getExistingHsmKek(), keyAlgorithm, iv, encryptedHostKey);
            }
            return secretKey;
        }

    }



    public static void main(String[] args) throws Exception {
        final String hostKeyType = "DESede"; // 3 DES

        HsmManager.login();

        //
        //  Create the HSM KEK (Key Encryption Key)
        //
        SecretKey kek = createNewHsm3desKek();
        out.println("HSM KEK (not in the clear):\n\t" + getHex(kek.getEncoded()));


        //
        //  Create a key that's not on the HSM for the purposes of this example
        //
        SecretKey hostKeyUnencrypted = createSoftwareKey(hostKeyType);
        byte[] hostKeyWrappingIv =  new byte[8];
        new SecureRandom().nextBytes(hostKeyWrappingIv);
        out.println("Initial Host Key (in the clear):\n\t " + getHex(hostKeyUnencrypted.getEncoded()));
        out.println("Wrapping IV for Host Key:\n\t "+ getHex(hostKeyUnencrypted.getEncoded()));

        //
        //  Use the HSM to wrap our host key
        //
        byte[] wrappedHostKey = wrapKeyWithKek(kek, hostKeyWrappingIv, hostKeyUnencrypted);
        out.println("KEK Wrapped Host Key:\n\t " + getHex(wrappedHostKey));

        //
        //  Put the encrypted host key in our serializable holder
        //
        SerializableKeyHolder keyHolder = new SerializableKeyHolder(hostKeyType, hostKeyWrappingIv, wrappedHostKey);


        //
        //  Serialize our holder into a byte array and destroy our reference to the original object
        //
        byte[] serializedBytes = SerializationUtils.serialize(keyHolder);
        keyHolder = null;
        out.println("Serialized Key Holder:\n\t" + getHex(serializedBytes));

        //
        //  Show that the IV and the encrypted key are subarrays of the serialized data, but that
        //  the unencrypted key is not.  It doesn't prove that the unencrypted key isn't there, but
        //  it's a sanity check nonetheless.
        //
        int indexOfIvInSerializedData = Bytes.indexOf(serializedBytes, hostKeyWrappingIv);
        out.println("Index of IV in Serialized Data:\n\t" + indexOfIvInSerializedData);
        int indexOfEncryptedKeyInSerializedData = Bytes.indexOf(serializedBytes, wrappedHostKey);
        out.println("Index of Encrypted Key in Serialized Data:\n\t" + indexOfEncryptedKeyInSerializedData);
        int indexOfUnencryptedKeyInSerializedData = Bytes.indexOf(serializedBytes, hostKeyUnencrypted.getEncoded());
        out.println("Index of Unencrypted Key in Serialized Data:\n\t" + indexOfUnencryptedKeyInSerializedData);


        //
        //  Reconstitute (deserialize) the holder from the byte array
        //
        keyHolder = SerializationUtils.deserialize(serializedBytes);

        out.println("Deserialized and Unwrapped Host Key (same as original):\n\t" +
                getHex(keyHolder.getSecretKey().getEncoded()));



        //
        //  Encrypt and decrypt some meaningless data using the HSM just for kicks!
        //
        byte[] plainText = LunaUtils.hexStringToByteArray("DEADD00D8BADF00DDEADBABED15EA5ED");
        out.println("Plain Text:\n\t" + getHex(plainText));

        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding", "LunaProvider");
        SecretKey hostKey = keyHolder.getSecretKey();
        cipher.init(Cipher.ENCRYPT_MODE, hostKey);
        byte[] cipherText = cipher.doFinal(plainText);
        out.println("Cipher Text:\n\t" + getHex(cipherText));
        cipher.init(Cipher.DECRYPT_MODE, hostKey);

        byte[] plainTextDecrypted = cipher.doFinal(cipherText);
        out.println("Plain Text Decrypted:\n\t" + getHex(plainTextDecrypted));

        HsmManager.logout();
    }


    //  KEK is generated on HSM.  We never know its value, just it's alias name.
    private static SecretKey createNewHsm3desKek()  throws GeneralSecurityException {

        if (HsmManager.hasSavedKey(KEK_ALIAS)) {
            HsmManager.deleteKey(KEK_ALIAS);
        }

        KeyGenerator kg = KeyGenerator.getInstance("DESede", "LunaProvider");
        kg.init(256);
        LunaSecretKey kek = (LunaSecretKey) kg.generateKey();

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
    private static byte[] wrapKeyWithKek(SecretKey hsmKek, byte[] wrappingIv, SecretKey keyToBeWrapped) throws GeneralSecurityException {
        Cipher wrappingCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", "LunaProvider");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("IV", "LunaProvider");
        algParams.init(new IvParameterSpec(wrappingIv));
        wrappingCipher.init(Cipher.WRAP_MODE, hsmKek, algParams);
        return  wrappingCipher.wrap(keyToBeWrapped);
    }


    private static SecretKey unwrapKeyWithKek(SecretKey hsmKek, String wrappedKeyAlgo, byte[] wrappedKeyIv, byte[] wrappedKeyBytes) throws GeneralSecurityException {
        Cipher wrappingCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", "LunaProvider");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("IV", "LunaProvider");
        algParams.init(new IvParameterSpec(wrappedKeyIv));
        wrappingCipher.init(Cipher.UNWRAP_MODE, hsmKek, algParams);
        return  (SecretKey) wrappingCipher.unwrap(wrappedKeyBytes, wrappedKeyAlgo, Cipher.SECRET_KEY);
    }


    private static String getHex(byte array[]) {
        return "0x" + LunaUtils.getHexString(array, false).toUpperCase();
    }

}
