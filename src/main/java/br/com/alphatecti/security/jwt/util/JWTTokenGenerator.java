package br.com.alphatecti.security.jwt.util;

import br.com.alphatecti.security.base.util.ConsoleUtils;
import br.com.alphatecti.security.jwt.parser.JWTInternalTokenParser;

/**
 * Utility class that generates a JWT Token using a main method
 * 
 * @author vhrodriguesv
 */
public class JWTTokenGenerator {

    /**
     * Main method to encode passwords
     */
    public static void main(String[] args) {
        try {
            System.out.print("Welcome to JWT token generator.\n");
            System.out.print("Type token secret.\n");
            String secret = ConsoleUtils.readTextFromConsole();
            if (secret != null && !"".equals(secret)) {
                System.out.print("Type token exp time in seconds.\n");
                String expTime = ConsoleUtils.readTextFromConsole();
                if (expTime != null && !"".equals(expTime)) {
                    long expirationTimeInMilis = Long.parseLong(expTime) * 1000; 
                    System.out.print("Type username or token subject.\n");
                    String subject = ConsoleUtils.readTextFromConsole();
                    String jwtToken = getJWTToken(secret, expirationTimeInMilis, subject);
                    System.out.print("The JWT token is: " + jwtToken);
                } else {
                    System.out.println("Invalid expiration time.\n");
                }
            } else {
                System.out.println("Invalid token secret.\n");
            }
        } catch (NumberFormatException nex) {
            System.out.println("Expiration time must be a valid integer number.\n");
        } catch (Exception ex) {
            System.out.println("Exception was throw.\n");
            ex.printStackTrace();
        }
    }

    public static String getJWTToken(String secret, long expTimeMs, String subject) {
        return new JWTInternalTokenParser(secret, expTimeMs).createJWTToken(subject);
    }
}
