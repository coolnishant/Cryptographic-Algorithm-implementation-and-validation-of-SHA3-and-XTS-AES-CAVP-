
package sha3bit;

/*
**********Authors**********
        Nishant Raj
        Suraj Kumar
***************************
*/

/*
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
    int inputlength, outputlength;
    String Msg, MD;
}
public class TestReadFile {
    //Change Primary File location
    final static String primaryLocation = "C:/Users/balki4/Desktop/iiscecdsa/test vector/sha-3bittestvectors/";
        
    public static void main(String[] args) throws FileNotFoundException,IOException {
        
        String[] alllocation = {"SHA3_224ShortMsg.rsp","SHA3_224LongMsg.rsp","SHA3_256ShortMsg.rsp",
            "SHA3_256LongMsg.rsp","SHA3_384ShortMsg.rsp","SHA3_384LongMsg.rsp",
        "SHA3_512ShortMsg.rsp","SHA3_512LongMsg.rsp"};
        
        System.out.println("Please wait!");
        for (int i = 0; i < alllocation.length; i++) {
            SHA3ValidationToFile(primaryLocation+alllocation[i]);
            System.out.print("!");
        }
        System.out.println("All File Validated Successfully!");
    }
    
    public static void SHA3ValidationToFile(String location) throws FileNotFoundException, IOException {
        //Enter the file name
        FileReader file = new FileReader(location);
        BufferedReader reader = new BufferedReader(file);
        String text = "";
        String line = reader.readLine();
        String has = "#";
        int count = 0;
        while(line.contains(has)){
            line = reader.readLine();
            continue;
        }
        text = reader.readLine();
        String s;
        s = text.substring(text.indexOf("[") + 1);
        s = s.substring(0, text.indexOf("]")-1);
        
        s = s.substring(s.indexOf("=")+1);
        s = s.trim();
        MyMessage mm = new MyMessage();
        mm.outputlength = Integer.parseInt(s);
       
        String output = "****Validated by**********\r\n"
                + "Nishant Raj\r\n"
                + "Suraj Kumar\r\n"
                + "***************************\r\n";
                output += location.substring(location.lastIndexOf("/")+1)+"\r\n\r\n";
        text = reader.readLine();
        while(line != null){
            line = reader.readLine();
            if(line != null){
                if(line.contains("Len =")){
                    mm.inputlength = Integer.parseInt(line.substring(line.indexOf("=")+1).trim());
                }
                else if(line.contains("Msg =")){
                    mm.Msg = line.substring(line.indexOf("=")+1).trim();
                }
                else if(line.contains("MD =")){
                    mm.MD = line.substring(line.indexOf("=")+1).trim();
                    //Call to SHA3 functions
                    String msgHash = SHA3BitOriented.getSHA3Hash(mm);
                    output += "Len: "+mm.inputlength+"\r\nMsg: "+mm.Msg+"\r\nOrginal MD: "+mm.MD+"\r\nOutputed MD: "+msgHash;
                    if(mm.MD.compareTo(msgHash) == 0){
                        count++;
                        output += "\r\nCheck OK";
                    }
                    output += "\r\n\r\n\r\n";
                }
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
