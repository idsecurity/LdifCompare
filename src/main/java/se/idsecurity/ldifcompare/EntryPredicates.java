/* 
 * Copyright (C) 2015-2017 almu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package se.idsecurity.ldifcompare;

import com.unboundid.ldap.sdk.Entry;
import java.util.function.Predicate;

/**
 * Predicates used by the compare framework  
 * @author almu
 */
public class EntryPredicates {
    
    /**
     * Indicates whether this entry contains an attribute with the provided name and value 
     * @param attributeName
     * @param attributeValue
     * @return 
     */
    public static Predicate<Entry> hasAttributeValue(String attributeName, String attributeValue) {
        return p -> attributeValue != null && p.hasAttributeValue(attributeName, attributeValue);
    }
    
    /**
     * Indicates whether this entry contains the specified attribute.
     * @param attributeName
     * @return 
     */
    public static Predicate<Entry> hasAttribute(String attributeName) {
        return p -> p.hasAttribute(attributeName);
    }
    
    /**
     * Indicates whether this entry doesn't contain an attribute with the provided name and value
     * @param attributeName
     * @param attributeValue
     * @return 
     */
    public static Predicate<Entry> doesntMatch(String attributeName, String attributeValue) {
        return (p) -> attributeValue != null && !p.hasAttributeValue(attributeName, attributeValue);
    }
}
