
package xtsaes;

/*
**********Authors**********
        Nishant Raj
        Suraj Kumar
***************************
*/

/*
    File description:
      File read, doing validation and storing to file.
*/
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;


class MyMessage{
    int COUNT, DataUnitLen, AESType, DataUnitSeqNumber;
    String Key, i, PT, CT;

    public MyMessage() {
        COUNT = 0;
        DataUnitLen = 128;
        AESType = 128;
        CT = null;
        PT = null;
        i = null;
        Key =null;
        DataUnitSeqNumber = -1;
    }
    
}
public class TestReadFile {
    //Change Primary File location
    static String primaryLocation = "C:/Users/Nishant/Google Drive/nitkcourse/Intership/IISC/XTS/Project Code/XTSTestVectors/";
        
    public static void main(String[] args) throws FileNotFoundException,IOException, Exception {
        int k=2;// k = 1
        String tweakas[] = {"format tweak value input - 128 hex str", "format tweak value input - data unit seq no"};
        for(int j=0;j<k;j++){
            String templocation = primaryLocation + tweakas[j]+"/";
            String[] alllocation = {"XTSGenAES128.rsp","XTSGenAES256.rsp"};

            System.out.println("Please wait!");
            for (int i = 0; i < alllocation.length; i++) {
                System.out.println("\nInput File: "+alllocation[i]+"\n");
                XTSAESValidationToFile(templocation+alllocation[i]);
                System.out.print("!");
            }
        }
        System.out.println("All File Validated Successfully!");
    }
    
    public static void XTSAESValidationToFile(String location) throws FileNotFoundException, IOException, Exception {
        //Enter the file name
//        String location = "C:/Users/balki4/Desktop/iiscecdsa/test vector/sha-3bittestvectors/SHA3_224ShortMsg.rsp";
        int AEStype = 128;
        FileReader file = new FileReader(location);
        BufferedReader reader = new BufferedReader(file);
        String text = "";
        String line = reader.readLine();
        String has = "#";
        int count = 0;
        while(line.contains(has)){
            line = reader.readLine();
            if(line.contains("Key Length"))
                AEStype = Integer.parseInt(line.trim().substring(line.indexOf("AES")+3));
        }
        text = reader.readLine();
        MyMessage mm = new MyMessage();
       
        String output = "*******Validated  by********\r\n"
                + "\r\tNishant Raj\r\n"
                + "\r\tSuraj Kumar\r\n"
                + "***************************\r\n"
                + "XTSAES NIST test vector Validation \r\n\r\nSource File: ";
                output += location.substring(location.lastIndexOf("/")+1)+"\r\n\r\n";
        text = reader.readLine();
        while(line != null){
            line = reader.readLine();
           if(line != null)
                if(line.contains("COUNT =")){
                    mm = new MyMessage();
                    mm.AESType = AEStype;
                    mm.COUNT = Integer.parseInt(line.substring(line.indexOf("=")+1).trim());
                }
                else if(line.contains("DataUnitLen =")){
                    mm.DataUnitLen = Integer.parseInt(line.substring(line.indexOf("=")+1).trim());
                }
                else if(line.contains("Key =")){
                    mm.Key = line.substring(line.indexOf("=")+1).trim();
                }
                else if(line.contains("i =")){
                    mm.i = line.substring(line.indexOf("=")+1).trim();
                }
                else if(line.contains("DataUnitSeqNumber =")){
                    mm.DataUnitSeqNumber = Integer.parseInt(line.substring(line.indexOf("=")+1).trim());
                }
                else if(line.contains("CT =")){
                    mm.CT = line.substring(line.indexOf("=")+1).trim();
                }
                else if(line.contains("PT =")){
                    mm.PT = line.substring(line.indexOf("=")+1).trim();
                }
                else if(mm.PT!=null && mm.CT !=null){
                    //Call to XTS functions
                    String check[] = null;
                    if(mm.DataUnitSeqNumber == -1){
                        output += "COUNT: "+mm.COUNT+"\r\nDataUnitLen : "+mm.DataUnitLen+"\r\nKey : "+mm.Key+"\r\ni : "+mm.i+"\r\nPT : "+mm.PT+"\r\nCT : "+mm.CT;
                    
                         check = XTSAES2.callXTSAES(mm.Key, mm.i, mm.PT, mm.CT, mm.DataUnitLen, mm.AESType);
                    }
                    else{
                        output += "COUNT: "+mm.COUNT+"\r\nDataUnitLen : "+mm.DataUnitLen+"\r\nKey : "+mm.Key+"\r\nDataUnitSeqNumber : "+mm.DataUnitSeqNumber+"\r\nPT : "+mm.PT+"\r\nCT : "+mm.CT;
                        System.out.println("dataseq");
                         check = XTSAES2.callXTSAES(mm.Key, mm.DataUnitSeqNumber, mm.PT, mm.CT, mm.DataUnitLen, mm.AESType);
                    }
                    if(check[0].equals(mm.CT)){
                        output += "\r\nCT generated: "+check[0];
                        System.out.println("Check CT Ok\n");
                    }
                     if(check[1].equals(mm.PT)){
                        output += "\r\nPT generated: "+check[1];
                        System.out.println("Check PT Ok\n");
                    }
                     if(check[0].equals(mm.CT) && check[1].equals(mm.PT)){
                         count++;
                         
                        output += "\r\nCheck OK";
                     }
                    output += "\r\n\r\n\r\n";
                    mm.PT = null;
                    mm.CT = null;
                }
        }
        System.out.println("Count: "+count);
        reader.close();
        //File Write
        File newFile = new File(location.substring(0, location.length()-4)+"out.rsp");
        if(newFile.exists()){
            System.out.println("File Already Exists!\nThen deleted\n");
            boolean result = Files.deleteIfExists(newFile.toPath());
        }
            try{
                newFile.createNewFile();
            }
            catch(Exception e){
                e.printStackTrace();
            }
            try{
                PrintWriter bw = new PrintWriter(newFile);
                bw.write(output);
                bw.close();
            }
            catch(Exception e){
                e.printStackTrace();
            }
        
    }
    
}


