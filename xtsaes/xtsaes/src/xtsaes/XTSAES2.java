
package xtsaes;

/*
**********Authors**********
        Nishant Raj
        Suraj Kumar
***************************
*/

/*
File description:
    XTSAES implementation: tested on NIST test vector
*/

public class XTSAES2 {
    private static int AES_BLK_BYTES = 16;  
    private static int GF_128_FDBK = 0x87;                    
    private static int KEY_LENGTH_HEX = 64;                
  
 
public String excyptionAESXTS(String key, String plain, String cipher, String i, int DataUnitLen) throws Exception {
    String baca = key;
    String key1 = baca.substring(0, KEY_LENGTH_HEX / 2);
    String key2 = baca.substring(KEY_LENGTH_HEX / 2, baca.length());
//    System.out.println("key1\t= " + key1);
//    System.out.println("key2\t= " + key2);
    return outXTSEncryptV2(Util.hex2byte(key1), Util.hex2byte(key2), Util.hex2byte(i), Util.hex2byte(plain), DataUnitLen);
//    System.out.println("Encryption Done!");
}
 
public String decyptionAESXTS(String key, String plain, String cipher, String i, int DataUnitLen) throws Exception {
    String baca = key;
    String key1 = baca.substring(0, KEY_LENGTH_HEX / 2);
    String key2 = baca.substring(KEY_LENGTH_HEX / 2, baca.length());
//    System.out.println("key1\t= " + key1);
//    System.out.println("key2\t= " + key2);
    return outXTSDecryptV2(Util.hex2byte(key1), Util.hex2byte(key2), Util.hex2byte(i), Util.hex2byte(cipher), DataUnitLen);
//    System.out.println("Decryption Done!");
}


public static void main(String[] args) throws Exception {
        String key = "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7cd6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08";
        String i = "adf8d92627464ad2f0428e84a9f87564";
        String ct = "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db";
        String pt = "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e";
        int DataUnitLen = 130;
        
        System.out.println("Input : "+pt);
        
        XTSAES2 xtsaes = new XTSAES2();
        xtsaes.excyptionAESXTS(key, pt, ct, i, DataUnitLen);
        
        System.out.println(ct);
        
        System.out.println("Input : "+ct);
        
        xtsaes.decyptionAESXTS(key, pt, ct, i, DataUnitLen);
        
        System.out.println(pt);
        
    }

//Call XTS using tweak i
public static String[] callXTSAES(String key, String i, String pt, String ct, int DataUnitLength, int AEStype) throws Exception {
        int DataUnitLen = 130;
        KEY_LENGTH_HEX = AEStype/2;
        String res[] = new String[2];
        XTSAES2 xtsaes = new XTSAES2();
        String outString = xtsaes.excyptionAESXTS(key, pt, ct, i, DataUnitLen).trim();
        System.out.println("in ct: "+ct);
        System.out.println("out ct: "+outString);
        res[0] = outString;
        outString = xtsaes.decyptionAESXTS(key, pt, ct, i, DataUnitLen).trim();
        System.out.println("in pt: "+pt);
        System.out.println("out pt: "+outString);
        res[1] = outString;
        return res;
    }

//Call XTS using data sequence number
public static String[] callXTSAES(String key, int DataSeqNumber, String pt, String ct, int DataUnitLength, int AEStype) throws Exception {
        KEY_LENGTH_HEX = AEStype/2;
        String i = Util.toHEX1(DataSeqNumber);
        String[] res = new String[2];
        i = i.substring(i.length()-2);
        for(int j = i.length();j<32;j++)
            i += "0";
        
        XTSAES2 xtsaes = new XTSAES2();
        String outString = xtsaes.excyptionAESXTS(key, pt, ct, i, DataUnitLength).trim();
        System.out.println("in ct: "+ct);
        System.out.println("out ct: "+outString);
        res[0] = outString;
        outString = xtsaes.decyptionAESXTS(key, pt, ct, i, DataUnitLength).trim();
        System.out.println("in pt: "+pt);
        System.out.println("out pt: "+outString);
        res[1] = outString;
        return res;
    }



private String outXTSEncryptV2(byte[] key1, byte[] key2, byte[] tweak, byte[] pt, int DataUnitLen) {
        int i,j;
        byte x[] = new byte[AES_BLK_BYTES];
        byte ct[] = new byte[pt.length];
        byte cin, cout = 0;
        int N = pt.length;
        AES aes = new AES();
        aes.setKey(key2);
        tweak = aes.encrypt(tweak);
        for(i=0;i+AES_BLK_BYTES<=N;i+=AES_BLK_BYTES){
            for(j=0;j<AES_BLK_BYTES;j++)
                x[j] = (byte) (pt[i+j] ^ tweak[j]);
        
            aes.setKey(key1);
            x = aes.encrypt(x);

            for(j=0;j<AES_BLK_BYTES;j++){
                ct[i+j] = (byte) (x[j] ^ tweak[j]);
            }
            //multiply T by alpha
            cin=0;
            for(j=0;j<AES_BLK_BYTES;j++){
                cout = (byte) ((tweak[j]>>>7) & 1);
                tweak[j] = (byte) (((tweak[j] << 1)+cin) & 0xFF);
                cin = cout;
//                System.out.println("cout: "+cout);
            }
            if(cout != 0)
                tweak[0] ^= GF_128_FDBK;
        }
        //N = 17 (130)
        //MULTIPLE OF 8
        if(DataUnitLen %8 ==0){
            if(i<N){
                for(j=0;i+j<N;j++){
                    x[j] = (byte) (pt[i+j] ^ tweak[j]);
                    ct[i+j] = ct[i+j-AES_BLK_BYTES];
                }
                for (;j < AES_BLK_BYTES; j++) {
                    x[j] = (byte) (ct[i+j-AES_BLK_BYTES] ^ tweak[j]);
                }
                aes.setKey(key1);
                x = aes.encrypt(x);
                for(j=0;j<AES_BLK_BYTES;j++){
                    ct[i+j-AES_BLK_BYTES] = (byte) (x[j] ^tweak[j]);
                }
            }
        }
        //NOT MULTIPLE OF 8
        else{
            if(i<N){
                for(j=0;i+j<N-1;j++){
                    x[j] = (byte) ((byte)(pt[i+j]) ^ tweak[j]);
                    ct[i+j] = (byte) ((byte)(ct[i+j-AES_BLK_BYTES]));
                }
//                j--;
                
                ct[i+j] = (byte) ((byte)(ct[i+j-AES_BLK_BYTES]&0xc0));
                x[j] = (byte) ((byte)((byte)(ct[i+j-AES_BLK_BYTES]&0x3f) | (byte)(pt[i+j]&0xc0)) ^ tweak[j]);
                
                for (j++;j < AES_BLK_BYTES; j++) {
                    x[j] = (byte) (ct[i+j-AES_BLK_BYTES] ^ tweak[j]);
                }
                aes.setKey(key1);
                x = aes.encrypt(x);
                for(j=0;j<AES_BLK_BYTES;j++){
                    ct[i+j-AES_BLK_BYTES] = (byte) (x[j] ^tweak[j]);
                }
            }
        }
        String output = "";
        for(i =0;i<N;i++){
            output += Util.toHEX1(ct[i]);
        }
        return output;
    }

    
private String outXTSDecryptV2(byte[] key1, byte[] key2, byte[] tweak, byte[] ct, int DataUnitLen) {
        int i=0,j;
        byte x[] = new byte[AES_BLK_BYTES];
        byte temptweak[] = new byte[tweak.length];
        byte pt[] = new byte[ct.length];
        byte cin, cout = 0;
        int N = ct.length;
//        System.out.println("N : "+pt[16]);
        AES aes = new AES();
        aes.setKey(key2);
        tweak = aes.encrypt(tweak);
        //NORMAL BLOCKS
        if(N%16 == 0){
            for(i=0;i<N;i+=AES_BLK_BYTES){
                for(j=0;j<AES_BLK_BYTES;j++)
                    x[j] = (byte) (ct[i+j] ^ tweak[j]);

                aes.setKey(key1);
                x = aes.decrypt(x);

                for(j=0;j<AES_BLK_BYTES;j++){
                    pt[i+j] = (byte) (x[j] ^ tweak[j]);
                }
                //multiply T by alpha
                cin=0;
                for(j=0;j<AES_BLK_BYTES;j++){
                    cout = (byte) ((tweak[j]>>>7) & 1);
                    tweak[j] = (byte) (((tweak[j] << 1)+cin) & 0xFF);
                    cin = cout;
                }
                if(cout != 0)
                    tweak[0] ^= GF_128_FDBK;
            }
        }
        else{
            
            //N not multiple of 16
            for(i=0;i+2*AES_BLK_BYTES<N;i+=AES_BLK_BYTES){
                for(j=0;j<AES_BLK_BYTES;j++)
                    x[j] = (byte) (ct[i+j] ^ tweak[j]);
                System.out.println("inside 32");
                aes.setKey(key1);
                x = aes.decrypt(x);

                for(j=0;j<AES_BLK_BYTES;j++){
                    pt[i+j] = (byte) (x[j] ^ tweak[j]);
                }
                //multiply T by alpha
                cin=0;
                for(j=0;j<AES_BLK_BYTES;j++){
                    cout = (byte) ((tweak[j]>>>7) & 1);
                    tweak[j] = (byte) (((tweak[j] << 1)+cin) & 0xFF);
                    cin = cout;
                }
                if(cout != 0)
                    tweak[0] ^= GF_128_FDBK;
            }
            
            //Save Old tweak
            //multiply T by alpha
            cin =0;
                for(j=0;j<AES_BLK_BYTES;j++){
                    
                    temptweak[j] = tweak[j]; 
                    cout = (byte) ((tweak[j]>>>7) & 1);
                    tweak[j] = (byte) (((tweak[j] << 1)+cin) & 0xFF);
                    cin = cout;
                }
                if(cout != 0)
                    tweak[0] ^= GF_128_FDBK;
        
            //using new alpha j(m) decrypt C  m-1
            for(j=0;j<AES_BLK_BYTES;j++)
                    x[j] = (byte) (ct[i+j] ^ tweak[j]);

                aes.setKey(key1);
                x = aes.decrypt(x);

                for(j=0;j<AES_BLK_BYTES;j++){
                    pt[i+j] = (byte) (x[j] ^ tweak[j]);
                }
                
                i+=AES_BLK_BYTES;
                        
        //MULTIPLE OF 8
        if(DataUnitLen %8 ==0){
            if(i<N){
                for(j=0;i+j<N;j++){
                    x[j] = (byte) (ct[i+j] ^ temptweak[j]);
                    pt[i+j] = pt[i+j-AES_BLK_BYTES];
                }
                for (;j < AES_BLK_BYTES; j++) {
                    x[j] = (byte) (pt[i+j-AES_BLK_BYTES] ^ temptweak[j]);
                }
                aes.setKey(key1);
                x = aes.decrypt(x);
                for(j=0;j<AES_BLK_BYTES;j++){
                    pt[i+j-AES_BLK_BYTES] = (byte) (x[j] ^temptweak[j]);
                }
            }
        
        }
        //NOT MULTIPLE OF 8
        else{
            if(i<N){
                for(j=0;i+j<N-1;j++){
                    x[j] = (byte) ((byte)(ct[i+j]) ^ temptweak[j]);
                    pt[i+j] =  ((byte)(pt[i+j-AES_BLK_BYTES]));
                }

                pt[i+j] = (byte) ((byte)(pt[i+j-AES_BLK_BYTES]&0xc0));
                x[j] = (byte) ((byte)((byte)(pt[i+j-AES_BLK_BYTES]&0x3f) | (byte)(ct[i+j]&0xc0)) ^ temptweak[j]);
                
                for (j++;j < AES_BLK_BYTES; j++) {
                    x[j] = (byte) (pt[i+j-AES_BLK_BYTES] ^ temptweak[j]);
                }
                aes.setKey(key1);
                x = aes.decrypt(x);
                for(j=0;j<AES_BLK_BYTES;j++){
                    pt[i+j-AES_BLK_BYTES] = (byte) (x[j] ^temptweak[j]);
                }
            }
        }
    }
    String outString = "";
        for(i =0;i<N;i++){
                outString += Util.toHEX1(pt[i]);
            
        }
        return outString;
    }    
}

