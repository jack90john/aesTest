import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 任务：
 * 描述：
 * 作者：蒋珂
 * 时间：2016/10/11 10:24
 * 类名: aesTest
 *
 * @version 1.0
 */
public class AESTool {
    /**
     * @description AES加密
     * @param content
     * @param password
     * @return byte[]
     */
    public static byte[] encrypt(String content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(getKeyByStr(password));
            kgen.init(128, random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            byte[] byteContent = content.getBytes("UTF-8");
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(byteContent);
            return result; // 加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @description AES解密
     * @param content
     * @param password
     * @return byte[]
     */
    public static byte[] decrypt(byte[] content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(getKeyByStr(password));
            kgen.init(128, random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(content);
            return result; // 加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] getKeyByStr(String str){
        byte[] bRet = new byte[str.length()/2];

        for(int i=0;i< str.length()/2;i++){

            Integer itg =new Integer(16*getChrInt(str.charAt(2*i)) + getChrInt(str.charAt(2*i+1)));

            bRet[i] = itg.byteValue();

        }
        return bRet;
    }

    public static int getChrInt(char chr){

        int iRet=0;

        if(chr=="0".charAt(0)) iRet = 0;

        if(chr=="1".charAt(0)) iRet = 1;

        if(chr=="2".charAt(0)) iRet = 2;

        if(chr=="3".charAt(0)) iRet = 3;

        if(chr=="4".charAt(0)) iRet = 4;

        if(chr=="5".charAt(0)) iRet = 5;

        if(chr=="6".charAt(0)) iRet = 6;

        if(chr=="7".charAt(0)) iRet = 7;

        if(chr=="8".charAt(0)) iRet = 8;

        if(chr=="9".charAt(0)) iRet = 9;

        if(chr=="A".charAt(0)) iRet = 10;

        if(chr=="B".charAt(0)) iRet = 11;

        if(chr=="C".charAt(0)) iRet = 12;

        if(chr=="D".charAt(0)) iRet = 13;

        if(chr=="E".charAt(0)) iRet = 14;

        if(chr=="F".charAt(0)) iRet = 15;

        return iRet;
    }

    /**
     * @description 解密加密串
     * @param contents 加密串
     * @return String
     */
    public static String decryptString(String contents, String password) throws Base64DecodingException {
        return new String(decrypt(Base64.decode(contents),password));
    }

    /**
     * @description 加密原始串
     * @param contents 原始字符串
     * @return String
     */
    public static String encryptString(String contents, String password){
        return Base64.encode(encrypt(contents,password));
    }
}
