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
        if (args.length != 3) {
            System.err.println("You need to set two comandline arguments.");
            System.err.println("% java Main [size] [filename] [key_size]");
            return;
        }
        int n = Integer.parseInt(args[0]);
        Random rnd = new Random();
        String filename1 = "gaus_" + args[1];
        String filename2 = "uni_" + args[1];
        String filename3 = "DPLDP_" + filename1;
        String filename4 = "DPLDP_" + filename2;
        String filename5 = "key_list.txt";
        int key_size = Integer.parseInt(args[2]);
        System.out.println("now generating");
        String newline = System.lineSeparator();
        try {
            FileWriter file_g1 = new FileWriter(filename1, true);
            PrintWriter pw_g1  = new PrintWriter(new BufferedWriter(file_g1));
            FileWriter file_g2 = new FileWriter(filename3, true);
            PrintWriter pw_g2  = new PrintWriter(new BufferedWriter(file_g2));
            FileWriter file_u1 = new FileWriter(filename2, true);
            PrintWriter pw_u1  = new PrintWriter(new BufferedWriter(file_u1));
            FileWriter file_u2 = new FileWriter(filename4, true);
            PrintWriter pw_u2  = new PrintWriter(new BufferedWriter(file_u2));
            FileWriter file    = new FileWriter(filename5, true);
            PrintWriter keylist = new PrintWriter(new BufferedWriter(file));
            int cnt = 0;
            pw_g2.print(String.valueOf(key_size) + newline);
            pw_u2.print(String.valueOf(key_size) + newline);

            for (int i = 0; i < key_size; i++) {
                String key = "key_" + Integer.toString(i) + newline;
                keylist.print(key);
            }

            for (int i = 0; i < n; i++) {
                double gaus = rnd.nextGaussian()*(key_size/10) + (key_size/2);
                int u = rnd.nextInt(key_size);
                int g = (int)Math.round(gaus);
                if (g < 0) g = 0;
                if (g > key_size) g = key_size;
                pw_g2.print(String.valueOf(g) + newline);
                pw_u2.print(String.valueOf(u) + newline);
                String keyg = "key_" + Integer.toString(g) + " ";
                StringBuilder sb_g = new StringBuilder(n);
                sb_g.append(keyg);
                sb_g.append(getRandomString() + newline);
                pw_g1.print(sb_g.toString());

                String keyu = "key_" + Integer.toString(u) + " ";
                StringBuilder sb_u = new StringBuilder(n);
                sb_u.append(keyu);
                sb_u.append(getRandomString() + newline);
                pw_u1.print(sb_u.toString());
                if (cnt == n/100) {
                    System.out.print("#");
                    cnt = 0;
                } else {
                    cnt++;
                }
            }
            System.out.println();
            pw_g1.close();
            pw_g2.close();
            pw_u1.close();
            pw_u2.close();
            keylist.close();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
