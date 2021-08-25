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
        int n = Integer.parseInt(args[0]) * 10000;
        Random rnd = new Random();
        String filename = args[1];
        System.out.println("now generating");
        String newline = System.lineSeparator();
        try {
            FileWriter file = new FileWriter(filename, true);
            PrintWriter pw = new PrintWriter(new BufferedWriter(file));
            int cnt = 0;

            for (int i = 0; i < n; i++) {
                double gaus = rnd.nextGaussian()*(n/5) + (n/2);
                StringBuilder sb = new StringBuilder(1000);
                int keyn = (int)Math.round(gaus);
                if (keyn <= 0) keyn = 0;
                if (keyn >= n) keyn = n;
                String key = "key_" + Integer.toString(keyn) + newline;
                sb.append(key);
                for (int j = 0; j < 10; j++)
                    sb.append(getRandomString() + newline);

                pw.print(sb.toString());
                System.out.println(i);
                //if (cnt == n/100) {
                //    System.out.print("#");
                //    cnt = 0;
                //} else {
                //    cnt++;
                //}
            }
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
