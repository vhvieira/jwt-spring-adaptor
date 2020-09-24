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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;


/**
 * Utility class for reflection
 * @author vhrodriguesv
 */
public class ReflectionUtils {

    /**
     * Helper method to set a value to a private static field. 
     * 
     * @param clazz
     *            the class containing the field
     * @param fieldName
     *            the name of the field to be modified
     * @param value
     *            the value to assign
     * @throws ReflectiveOperationException
     *             w hen fiel fied cannot be modified
     */
    public static void setFinalStaticField(Class<?> clazz, String fieldName, Object value) throws ReflectiveOperationException {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        Field modifiers = Field.class.getDeclaredField("modifiers");
        modifiers.setAccessible(true);
        modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, value);
    }
}
