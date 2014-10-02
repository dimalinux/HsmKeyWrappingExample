package to.noc.hsm.lunasa.example;

import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.key.LunaKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

import static java.lang.System.out;


/*
 * This is similar to the other KeyWrapping example, but in this example we generate all keys
 * on the HSM and call LunaSlotManager::setSecretKeysExtractable.  As before, the unwrapped
 * key is exposed to the application layer.
 *
 * Output from a sample run:
 *
 *     AES Key generated on HSM:
 *         0x834869E03E3054C127712883B0F7CB9716E2DF619D50002F164934EB9C5C7242
 *
 *     Class of key to wrap:
 *         class com.safenetinc.luna.provider.key.LunaSecretKey
 *
 *     Key to wrap:
 *         0xBD8B34A1649FB3EC9AF57DD157FA8BB9C2CCDB1C35D37CC51EB32EC39533509D
 *
 *     Wrapped Key:
 *         0xBF2DFCC8BB0679B01B03BF0CEB0F666C2C4E35A75743E39B678F1C3007E55F48E02B1DA8A90E227CF6DF6B2BBE8D1277
 *
 *     Unwrapped key (in clear same as original):
 *         0xBD8B34A1649FB3EC9AF57DD157FA8BB9C2CCDB1C35D37CC51EB32EC39533509D
 *
 *     Plain Text  ('SixteenByteClear'):
 *         0x5369787465656E42797465436C656172
 *
 *     Cipher Text:
 *         0x2F5542DA100B07AF26262A8E31050E85A6F554397AC6EAE161769C93FDC6E81A
 *
 */
public class KeyWrappingWithHsmGeneratedKeysExample {

    //
    //  AES block size is 128 bits or 16 bytes.  Used easy HEX values so you can plug them
    //  into a website like http://aes.online-domain-tools.com/ to verify encrypted values.
    //
    private static final IvParameterSpec FIXED_128BIT_IV_FOR_TESTS = new IvParameterSpec(
            LunaUtils.hexStringToByteArray("DEADD00D8BADF00DDEADBABED15EA5ED")
    );


    public static void main(String[] args) throws Exception {

        HsmManager.login();
        HsmManager.setSecretKeysExtractable(true);

        KeyGenerator lunaKeyGenerator = KeyGenerator.getInstance("AES", "LunaProvider");
        Cipher lunaAesCbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");

        //
        //  Generate a wrapping key (KEK: Key Encryption Key) using the Luna SA HSM.
        //  OpenJDK handles AES 256 just fine, but I had to back this down to 128 for
        //  Oracle's JDK which, by default, has strong crypto disabled.
        //
        lunaKeyGenerator.init(128);
        Key kek = lunaKeyGenerator.generateKey();


        //
        //  If we hadn't set setSecretKeysExtractable(true), the key printed below would
        //  just be an ID.  Since we did make secret keys extractable, the line below will
        //  print the actual key value in the clear.
        //
        out.println("AES Key generated on HSM: " + getHex(kek.getEncoded()));


        //
        //  Generate a second AES key to be wrapped.  As with the KEK above, the key printed
        //  below will be the actual key in the clear.
        //
        SecretKey keyToWrap = lunaKeyGenerator.generateKey();
        out.println("Class of key to wrap: " + keyToWrap.getClass());
        out.println("Key to wrap: " + getHex(keyToWrap.getEncoded()));


        //
        //  Wrap the key
        //
        //    Note:  If you set 'setSecretKeysExtractable' above to false, this exception
        //           will be thrown during the call to 'wrap':
        //
        //                  LunaCryptokiException: function 'C_WrapKey' returns 0x6a
        //
        //           0x6a is 'CKR_KEY_UNEXTRACTABLE'
        //
        lunaAesCbcCipher.init(Cipher.WRAP_MODE, kek, FIXED_128BIT_IV_FOR_TESTS);
        byte[] wrappedKey = lunaAesCbcCipher.wrap(keyToWrap);
        out.println("Wrapped Key: " + getHex(wrappedKey));


        //
        //  Unwrap the key
        //
        lunaAesCbcCipher.init(Cipher.UNWRAP_MODE, kek, FIXED_128BIT_IV_FOR_TESTS);
        LunaKey unwrappedKey = (LunaKey)lunaAesCbcCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        out.println("Unwrapped key (in clear same as original): " + getHex(unwrappedKey.getEncoded()));


        //
        //  Encrypt data with unwrapped key
        //
        lunaAesCbcCipher.init(Cipher.ENCRYPT_MODE, unwrappedKey, FIXED_128BIT_IV_FOR_TESTS);
        String plainTextStr = "SixteenByteClear";
        byte[] plainText = "SixteenByteClear".getBytes();
        byte[] cipherText = lunaAesCbcCipher.doFinal(plainText);
        out.println("Plain Text  ('" + plainTextStr + "'): " + getHex(plainText));
        out.println("Cipher Text: " + getHex(cipherText));

        unwrappedKey.DestroyKey();
        HsmManager.logout();
    }


    private static String getHex(byte array[]) {
        return "0x" + LunaUtils.getHexString(array, false).toUpperCase();
    }

}
