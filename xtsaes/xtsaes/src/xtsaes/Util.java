
package xtsaes;

/*
**********Authors**********
        Nishant Raj
        Suraj Kumar
***************************
*/

/*
    File description:
        Utility Functions
*/
class Util {

    public static final char[] HEX_DIGITS = {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };

    public static String toHEX (byte[] ba) {
        int length = ba.length;
        char[] buf = new char[length * 3];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
	    buf[j++] = ' ';
        }
        return new String(buf);
    }
    
    public static String toHEX (short[] ia) {
        int length = ia.length;
        char[] buf = new char[length * 5];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ia[i++];
            buf[j++] = HEX_DIGITS[(k >>>12) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 8) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
	    buf[j++] = ' ';
        }
        return new String(buf);
    }

    public static String toHEX (int[] ia) {
        int length = ia.length;
        char[] buf = new char[length * 10];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ia[i++];
            buf[j++] = HEX_DIGITS[(k >>>28) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>24) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>20) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>16) & 0x0F];
	    buf[j++] = ' ';
            buf[j++] = HEX_DIGITS[(k >>>12) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 8) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
	    buf[j++] = ' ';
        }
        return new String(buf);
    }

    public static String toHEX1 (byte b) {
        char[] buf = new char[2];
	int j = 0;
        buf[j++] = HEX_DIGITS[(b >>> 4) & 0x0F];
        buf[j++] = HEX_DIGITS[ b        & 0x0F];
        return new String(buf);
    }
    
    public static String toHEX1 (byte[] ba) {
        int length = ba.length;
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }
    
    public static String toHEX1 (short[] ia) {
        int length = ia.length;
        char[] buf = new char[length * 4];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ia[i++];
            buf[j++] = HEX_DIGITS[(k >>>12) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 8) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }
    
    public static String toHEX1 (int i) {
        char[] buf = new char[8];
	int j = 0;
        buf[j++] = HEX_DIGITS[(i >>>28) & 0x0F];
        buf[j++] = HEX_DIGITS[(i >>>24) & 0x0F];
        buf[j++] = HEX_DIGITS[(i >>>20) & 0x0F];
        buf[j++] = HEX_DIGITS[(i >>>16) & 0x0F];
        buf[j++] = HEX_DIGITS[(i >>>12) & 0x0F];
        buf[j++] = HEX_DIGITS[(i >>> 8) & 0x0F];
        buf[j++] = HEX_DIGITS[(i >>> 4) & 0x0F];
        buf[j++] = HEX_DIGITS[ i        & 0x0F];
        return new String(buf);
    }
    
    public static String toHEX1 (int[] ia) {
        int length = ia.length;
        char[] buf = new char[length * 8];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ia[i++];
            buf[j++] = HEX_DIGITS[(k >>>28) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>24) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>20) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>16) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>>12) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 8) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }
    
    public static byte[] hex2byte(String hex) {
        int len = hex.length();
        byte[] buf = new byte[((len + 1) / 2)];

        int i = 0, j = 0;
        if ((len % 2) == 1)
            buf[j++] = (byte) hexDigit(hex.charAt(i++));

        while (i < len) {
            buf[j++] = (byte) ((hexDigit(hex.charAt(i++)) << 4) |
                                hexDigit(hex.charAt(i++)));
        }
        return buf;
    }
    
    public static boolean isHex(String hex) {
        int len = hex.length();
	int i = 0;
	char ch;

	while (i < len) {
	     ch = hex.charAt(i++);
	     if (! ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') ||
	           (ch >= 'a' && ch <= 'f'))) return false;
	}
	return true;
    }
    
    public static int hexDigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;

        return(0);
    }

}
