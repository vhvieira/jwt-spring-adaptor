/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.base.util;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Console utility class
 * @author vhrodriguesv
 */
public class ConsoleUtils {
    
    /**
     * Read a text from console
     */
    public static String readTextFromConsole() {
        try {
            InputStreamReader streamReader = new InputStreamReader(System.in);
            BufferedReader bufferedReader = new BufferedReader(streamReader);
            return bufferedReader.readLine();
        } catch (IOException e) {
            return null;
        }
    }
    
    /**
     * Read a password from console
     */
    public static String readPasswordFromConsole() {
        Console console = System.console();
        if (console == null) {
            try {
                InputStreamReader streamReader = new InputStreamReader(System.in);
                BufferedReader bufferedReader = new BufferedReader(streamReader);
                return bufferedReader.readLine();
            } catch (IOException e) {
                return null;
            }
        } else {
            return new String(console.readPassword());
        }
    }

}
