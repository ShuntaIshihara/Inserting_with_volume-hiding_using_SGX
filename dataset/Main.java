import java.util.Random;
import java.nio.charset.*;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

class Main {
    public static String getRandomString() {
        byte[] bytearray = new byte[256];
        new Random().nextBytes(bytearray);
        String str = new String(bytearray, Charset.forName("UTF-8"));
        String theAlphaNumericS = str.replaceAll("[^A-Za-z0-9]", ""); 
        return theAlphaNumericS;
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("You need to set two comandline arguments.");
            return;
        }
        int n = Integer.parseInt(args[0]);
        Random rnd = new Random();
        String filename1 = args[1];
        String filename2 = "DP,LDP_" + filename1;
        System.out.println("now generating");
        String newline = System.lineSeparator();
        try {
            FileWriter file1 = new FileWriter(filename1, true);
            PrintWriter pw1 = new PrintWriter(new BufferedWriter(file1));
            FileWriter file2 = new FileWriter(filename2, true);
            PrintWriter pw2 = new PrintWriter(new BufferedWriter(file2));
            int cnt = 0;
            pw2.print(String.valueOf(n) + newline);

            for (int i = 0; i < n; i++) {
                double gaus = rnd.nextGaussian()*(100) + (500);
                StringBuilder sb = new StringBuilder(1000);
                int keyn = (int)Math.round(gaus);
                if (keyn <= 0) keyn = 0;
                if (keyn >= n) keyn = n-1;
                pw2.print(String.valueOf(keyn) + newline);
                String key = "key_" + Integer.toString(keyn) + newline;
                sb.append(key);
                sb.append(getRandomString() + newline);

                pw1.print(sb.toString());
                if (cnt == n/100) {
                    System.out.print("#");
                    cnt = 0;
                } else {
                    cnt++;
                }
            }
            System.out.println();
            pw1.close();
            pw2.close();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
