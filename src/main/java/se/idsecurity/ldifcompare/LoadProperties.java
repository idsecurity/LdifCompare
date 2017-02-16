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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Parses a Java property file
 * @see <a href="http://docs.oracle.com/javase/7/docs/api/java/util/Properties.html">Java Properties JavaDoc</a>
 * @author almu
 */
public class LoadProperties {

    private final File propertiesFile;
    private final Properties properties = new Properties();
    private boolean initialized = false;
    private final String matchAttributeNameProperty = "match-attribute";
    
    /**
     * Creates a new LoadProperties using the specified properties file
     * @param propertiesFile 
     */
    public LoadProperties(File propertiesFile) {
        this.propertiesFile = propertiesFile;
    }
    
    /**
     * Call this method once to load the properties file.
     * @throws FileNotFoundException
     * @throws IOException 
     */
    public void initialize() throws FileNotFoundException, IOException {
        FileInputStream propStream = new FileInputStream(propertiesFile);
        properties.load(propStream);
        initialized = true;
    }
    
    /**
     * Retrieves the Properties object associated with this properties file.
     * Call {@link #initialize()} before calling this method!
     * @return The Properties object
     */
    public Properties getProperties() {
        if (!initialized) {
            throw new IllegalStateException("Call initialize before calling this method.");
        }
        return properties;
    }
    
    /**
     * Return the value of a property.
     * @param key Name of the property
     * @return The value or null if there is no such property
     */
    public String getPropertyString(String key) {
        return getProperties().getProperty(key);
    }
    
    /**
     * Parse a comma separated property into a List of Strings
     * @param key Name of the property
     * @return The list of Strings or an empty list if there was no such property
     */
    public List<String> getCommaSeparatedPropertyAsList(String key) {
        String property = getPropertyString(key);
        List<String> list = new ArrayList<>();
        if (property != null && property.contains(",")) {
            
            String[] splitProperties = property.split(",");
            list.addAll(Arrays.asList(splitProperties));
            
        } 
        return list;
    }
    
    /**
     * Retrieves an MatchingAttributeNames object from the properties file.
     * @return The MatchingAttributeNames object or null if there is no such property in the file.
     */
    public MatchingAttributeNames getMatchingAttributeNames() {
        MatchingAttributeNames value = null;
        String property = getPropertyString(matchAttributeNameProperty);
        if (property != null) {
            String[] splitProperties = property.split(",");
            if (splitProperties.length == 2) {
                value = new MatchingAttributeNames(splitProperties[0], splitProperties[1]);
            } else {
                value = new MatchingAttributeNames(splitProperties[0], splitProperties[0]);
            }
        }
        return value;
    }
    
}
