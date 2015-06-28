/* 
 * Copyright (C) 2015 almu
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

import java.util.Objects;

/**
 * Represents an object that contains the name of the attributes to use when matching two Entry objects.
 * @author almu
 */
public final class MatchingAttributeNames {
    
    private final String left;
    private final String right;
    
    /**
     * Creates a new MatchingAttributeNames object using the specified attribute names
     * @param left The name of the matching attribute in the "left" LDIF file
     * @param right The name of the matching attribute in the "right" LDIF file
     */
    public MatchingAttributeNames(String left, String right) {
        if (left == null || right == null || left.isEmpty() || right.isEmpty()) {
            throw new IllegalArgumentException("The parameters left and right must not be null/empty");
        }
        this.left = left;
        this.right = right;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 71 * hash + Objects.hashCode(this.left);
        hash = 71 * hash + Objects.hashCode(this.right);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final MatchingAttributeNames other = (MatchingAttributeNames) obj;
        if (!Objects.equals(this.left, other.left)) {
            return false;
        }
        if (!Objects.equals(this.right, other.right)) {
            return false;
        }
        return true;
    }

    /**
     * Retrieve the name of the matching attribute in the "left" LDIF file
     * @return The attribute name
     */
    public String getLeft() {
        return left;
    }

    /**
     * Retrieve the name of the matching attribute in the "right" LDIF file
     * @return The attribute name
     */
    public String getRight() {
        return right;
    }
    
    
    
    
}
