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

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compares two LDIF files and writes the differences to a set of files
 * @author almu
 * 
 */
public class LdifCompare {
    private final static Logger logger = LoggerFactory.getLogger(LdifCompare.class);
    private final int SETSIZE = 30000;
    private final File leftLdif;
    private final File rightLdif;
    private final File entriesThatDiffOrDontExistsInLeftLdif;
    private final File diffFile;
    private final File entriesOnlyInLeftLdif;
    private final File entriesOnlyInRightLdif;
    
    
    private LDIFReader reader_leftLdif;
    private LDIFReader reader_rightLdif;
    private LDIFWriter writer_diffLdif;
    private LDIFWriter writer_entriesOnlyInLeftLdif;
    private LDIFWriter writer_entriesOnlyInRightLdif;
    
    private final List<String> attributesToIgnoreWhenComparing;
    
    /**
     * Attribute names to use for matching
     */
    private final Optional<MatchingAttributeNames> matchingAttributeNames;
    

    /**
     * Used for naming the output files
     */
    private final String date = "yyyy-MM-dd HHmmss";
    private final SimpleDateFormat sdf = new SimpleDateFormat(date);
    
    private final String fileNameDate = sdf.format(new Date(System.currentTimeMillis()));
    
    /**
     * After creating an instance of this class call the {@link #start() } method.
     * @param leftLdif The "left" LDIF file, i.e. the file that contains some "original" state data
     * @param rightLdif The "right" LDIF file, i.e. the file that contains data after some processing of the original data
     * @param outputDirectory The directory where the output files will be placed
     * @param attributesToIgnoreWhenComparing Attributes that will be removed from the LDIF entry before making a comparison, e.g. logonTime
     * @param matchingAttributeNames Attribute names to use for matching between the two files, may be null, then DN will be used for matching
     */
    public LdifCompare(File leftLdif, File rightLdif, File outputDirectory, List<String> attributesToIgnoreWhenComparing, MatchingAttributeNames matchingAttributeNames) {
        if (leftLdif == null || rightLdif == null || attributesToIgnoreWhenComparing == null) {
            throw new IllegalArgumentException("leftLdif, rightLdif, outputDirectory, attributesToIgnoreWhenComparing arguments may not be null!");
        }
        
        this.leftLdif = leftLdif;
        this.rightLdif = rightLdif;
        
        this.entriesThatDiffOrDontExistsInLeftLdif = new File(outputDirectory, fileNameDate + "-diff.ldif");
        this.diffFile = new File(outputDirectory, fileNameDate + "-change_records.txt");
        
        this.entriesOnlyInLeftLdif = new File(outputDirectory, fileNameDate + "-unique-" + leftLdif.getName());
        
        this.entriesOnlyInRightLdif = new File(outputDirectory, fileNameDate + "-unique-" + rightLdif.getName());
        
        this.attributesToIgnoreWhenComparing = attributesToIgnoreWhenComparing;
        
        this.matchingAttributeNames = Optional.ofNullable(matchingAttributeNames);
        
        for (String s : attributesToIgnoreWhenComparing) {
            logger.error("Attribute to ignore when comparing: {}", s);
        }
    }
    
    /**
     * Call this method to start the entire comparison process
     * @throws IOException 
     */
    public void start() throws IOException {
        reader_leftLdif = new LDIFReader(leftLdif);
        reader_rightLdif = new LDIFReader(rightLdif);
        writer_diffLdif = new LDIFWriter(entriesThatDiffOrDontExistsInLeftLdif);
        writer_entriesOnlyInLeftLdif = new LDIFWriter(entriesOnlyInLeftLdif);
        writer_entriesOnlyInRightLdif = new LDIFWriter(entriesOnlyInRightLdif);
        
        try {
            logger.error("Write comments to {}", entriesThatDiffOrDontExistsInLeftLdif.getPath());
            writer_diffLdif.writeVersionHeader();
            writer_diffLdif.writeComment("This file contains entries from " + rightLdif.getName() +  " that differ in some way from entries in " + leftLdif.getName(), false, true);
            
            logger.error("Write comments to {}", entriesOnlyInLeftLdif.getPath());
            writer_entriesOnlyInLeftLdif.writeVersionHeader();
            writer_entriesOnlyInLeftLdif.writeComment("Applicable only when matching using DN!", false, false);
            writer_entriesOnlyInLeftLdif.writeComment("This file contain entries that only exist in " + leftLdif.getName() + ", i.e. they are missing for some reason in " + rightLdif.getName() + " or have been renamed/moved and have a different DN.", false, true);
            
            logger.error("Write comments to {}", entriesOnlyInRightLdif.getPath());
            writer_entriesOnlyInRightLdif.writeVersionHeader();
            writer_entriesOnlyInRightLdif.writeComment("Applicable only when matching using DN!", false, false);
            writer_entriesOnlyInRightLdif.writeComment("This file contain entries that only exist in " + rightLdif.getName() + ", i.e. they are missing for some reason in " + leftLdif.getName() + " or have been renamed/moved and have a different DN.", false, true);
            
            
            
            logger.error("Reading file 1: {}", leftLdif.getPath());
            Set<Entry> entriesFromLeftFile = new HashSet<>(SETSIZE);
            while (true) {
               Entry entry = reader_leftLdif.readEntry();
                
                if (entry == null) {
                    break;
               }

                entriesFromLeftFile.add(removeIgnoredAttributesFromEntry(entry));
            }
            
            logger.error("Reading file 2: {}", rightLdif.getPath());
            Set<Entry> entriesFromRightFile = new HashSet<>(SETSIZE);
            while (true) {
               Entry entry = reader_rightLdif.readEntry();
                
                if (entry == null) {
                    break;
                }
                
                entriesFromRightFile.add(removeIgnoredAttributesFromEntry(entry));
            }

            //If matchingAttributeNames is available then will do a matching using attribute values instead of DN
            if (matchingAttributeNames.isPresent()) {
                logger.error("Will perform diff matching using attributes. " + leftLdif.getName() + ":" + matchingAttributeNames.get().getLeft() + ", " + rightLdif.getName() + ":" + matchingAttributeNames.get().getRight());
                //-change_records.txt
                getDiffUsingMatchingAttributes(entriesFromLeftFile, entriesFromRightFile, matchingAttributeNames.get().getLeft(), matchingAttributeNames.get().getRight(), matchingAttributeNames.get(), diffFile, "Matching entries in the FIRST LDIF file using the attribute '" + matchingAttributeNames.get().getRight() + "' from the SECOND LDIF file and displaying modifications that must be made to the entry in the FIRST LDIF file to match the entry from the SECOND LDIF file.");
                //-reverse-change_records.txt
                getDiffUsingMatchingAttributes(entriesFromRightFile, entriesFromLeftFile, matchingAttributeNames.get().getRight(), matchingAttributeNames.get().getLeft(), matchingAttributeNames.get(), new File(diffFile.getParentFile(), fileNameDate + "-reverse-change_records.txt"), "Matching entries in the SECOND LDIF file using the attribute '" + matchingAttributeNames.get().getLeft() + "' from the FIRST LDIF file and displaying modifications that must be made to the entry in the SECOND LDIF file to match the entry from the FIRST LDIF file.");
                
                File nonMatching = new File(diffFile.getParentFile(), fileNameDate + "-no-match.txt");
                File nonMatchingLdif = new File(nonMatching.getParent(), fileNameDate + "-no-match.ldif");
                getNonMatchingEntriesUsingMatchingAttributes(entriesFromLeftFile, entriesFromRightFile, matchingAttributeNames.get(), nonMatching, nonMatchingLdif);
                
                
                File reverseNonMatching = new File(diffFile.getParentFile(), fileNameDate + "-reverse-no-match.txt");
                File reverseNonMatchingLdif = new File(reverseNonMatching.getParentFile(), fileNameDate + "-reverse-no-match.ldif");
                getReverseNonMatchingEntriesUsingMatchingAttributes(entriesFromLeftFile, entriesFromRightFile, matchingAttributeNames.get(), reverseNonMatching, reverseNonMatchingLdif);
                
            } else {
                //Write the change records for entries that have the same DN but differ in some way
                logger.error("Will perform diff matching using DN");
                getMatchUsingDN(entriesFromLeftFile, entriesFromRightFile);
            }

        } catch (IOException | LDIFException e) {
            logger.error("Exception occured", e);
        } finally {
            try {
                writer_diffLdif.close();
            } catch (IOException close) { 
                logger.error("Error closing writer_diffLdif", close); 
            }
            try {
                writer_entriesOnlyInLeftLdif.close();
            } catch (IOException close) {
                logger.error("Error closing writer_entriesOnlyInLeftLdif", close);
            }
            try {
                writer_entriesOnlyInRightLdif.close();
            } catch (IOException close) {
                logger.error("Error closing writer_entriesOnlyInRightLdif", close);
            }
            try {
                reader_leftLdif.close();
            } catch (IOException close) {
                logger.error("Error closing reader_leftLdif", close);
            }
            
            try {
                reader_rightLdif.close();
            } catch (IOException close) {
                logger.error("Error closing reader_rightLdif", close);
            }   
        }
        
    }
    
    /**
     * Compare LDIF entries using DN, if the DN is the same in both entries then the entries should be compared
     * @param source Entries from the "left" file
     * @param target Entries from the "right" file
     * @param diffFile Write results to this file
     * @param comment Comment to write to the file
     * @throws FileNotFoundException 
     */
    private void getDiffUsingDN(Set<Entry> source, Set<Entry> target, File diffFile, String comment) throws FileNotFoundException { 
        try (PrintWriter writer = new PrintWriter(diffFile)) {
            
            writer.println(comment);
            for (Entry targetEntry : target) {
                for (Entry sourceEntry : source) {
                    if (sourceEntry.getDN().equals(targetEntry.getDN())) {
                        writer.println();
                        writer.println(targetEntry.getDN());
                        List<Modification> diff = Entry.diff(sourceEntry, targetEntry, false);
                        for (Modification mod : diff) {
                            writer.println(mod);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Strip ignored attributes from the LDIF entry before processing
     * @param entry
     * @return 
     */
    private Entry removeIgnoredAttributesFromEntry(Entry entry) {
        for (String s : attributesToIgnoreWhenComparing) {
            entry.removeAttribute(s);
        }
        return entry;
    }
    
    /**
     * Compare LDIF entries using a matching attribute, if the attribute value is the same in both entries then the entries should be compared
     * @param firstLdif Entries from the "left" file
     * @param secondLdif Entries from the "right" file
     * @param attributeName Attribute to use for matching
     * @param diffFile Write results to this file
     * @throws FileNotFoundException 
     */
    private void getDiffUsingMatchingAttributes(Set<Entry> firstLdif, Set<Entry> secondLdif, String attributeNameFirst, String attributeNameSecond, MatchingAttributeNames attributeName, File diffFile, String comment) throws FileNotFoundException {
        try (PrintWriter writer = new PrintWriter(diffFile)) {
            writer.println(comment);
            
            firstLdif.stream().filter(EntryPredicates.hasAttribute(attributeNameFirst)).forEach((first) -> {
                secondLdif.stream().filter(EntryPredicates.hasAttributeValue(attributeNameSecond, first.getAttributeValue(attributeNameFirst))).forEach((second) -> {
                    writer.println();
                    writer.println("Matched '" + first.getDN() + "' using value '" + second.getAttributeValue(attributeNameSecond) + "' with '" + second.getDN() + "'");
                    List<Modification> diff = Entry.diff(first, second, false);
                    if (diff.isEmpty()) {
                        writer.println("NO DIFF");
                    } else {
                        diff.stream().forEach(mod -> writer.println(mod));
                    }
                    
                });
            });

        }
    }
    
    /**
     * Retrieves entries that we are unable to match using a matching attribute and writes those entries to output files.
     * For each entry in the <b>left</b> file try to find a match in the <b>right</b> file.
     * @param firstLdif Entries from the "left" file
     * @param secondLdif Entries from the "right" file
     * @param attributeName Attribute to use for matching
     * @param diffFile Write results to this file
     * @param ldifFile Write LDIF entries to this file
     * @throws IOException 
     */
    private void getNonMatchingEntriesUsingMatchingAttributes(Set<Entry> firstLdif, Set<Entry> secondLdif, MatchingAttributeNames attributeName, File diffFile, File ldifFile) throws IOException {
        LDIFWriter ldifWriter = new LDIFWriter(ldifFile);
        ldifWriter.writeVersionHeader();

        PrintWriter writer = new PrintWriter(diffFile);
        writer.println("Unable to match entries in the FIRST LDIF file using the attribute '" + attributeName.getRight() + "' from the SECOND LDIF file.");

        firstLdif.stream().forEach((Entry first) -> {
            long count = secondLdif.stream().filter(EntryPredicates.hasAttributeValue(attributeName.getRight(), first.getAttributeValue(attributeName.getLeft()))).findFirst().map(Stream::of).orElse(Stream.empty()).count();
            if (count == 0L) {
                writer.println();
                writer.println("No match found '" + first.getDN() + "' using value '" + first.getAttributeValue(attributeName.getLeft()) + "'");

                try {

                    ldifWriter.writeEntry(first, "No match found '" + first.getDN() + "' using value '" + first.getAttributeValue(attributeName.getLeft()) + "'");
                } catch (IOException ex) {
                    throw new RuntimeException("Exception writing to " + ldifFile.getPath(), ex);
                }
            }
        });
        ldifWriter.close();
        writer.close();

    }
    
    /**
     * Retrieves entries that we are unable to match using a matching attribute and writes those entries to output files.
     * For each entry in the <b>right</b> file try to find a match in the <b>left</b> file.
     * @param firstLdif Entries from the "left" file
     * @param secondLdif Entries from the "right" file
     * @param attributeName Attribute to use for matching
     * @param diffFile Write results to this file
     * @param ldifFile Write LDIF entries to this file
     * @throws IOException 
     */
    private void getReverseNonMatchingEntriesUsingMatchingAttributes(Set<Entry> firstLdif, Set<Entry> secondLdif, MatchingAttributeNames attributeName, File diffFile, File ldifFile) throws IOException {
        LDIFWriter ldifWriter = new LDIFWriter(ldifFile);
        ldifWriter.writeVersionHeader();
        PrintWriter writer = new PrintWriter(diffFile);
        writer.println("Unable to match entries in the SECOND LDIF file using the attribute '" + attributeName.getLeft() + "' from the FIRST LDIF file.");

        secondLdif.stream().forEach((Entry second) -> {
            long count = firstLdif.stream().filter(EntryPredicates.hasAttributeValue(attributeName.getRight(), second.getAttributeValue(attributeName.getRight()))).findFirst().map(Stream::of).orElse(Stream.empty()).count();
            if (count == 0L) {
                writer.println();
                writer.println("No match found '" + second.getDN() + "' using value '" + second.getAttributeValue(attributeName.getRight()) + "'");

                try {

                    ldifWriter.writeEntry(second, "No match found '" + second.getDN() + "' using value '" + second.getAttributeValue(attributeName.getRight()) + "'");
                } catch (IOException ex) {
                    throw new RuntimeException("Exception writing to " + ldifFile.getPath(), ex);
                }
            }
        });
        ldifWriter.close();
        writer.close();

    }
    
    /**
     * Performs matching between LDIF files using the DN and the Entry objects equals method
     * First remove all entries from secondLdif that are exactly the same in as those in firstLdif.
     * Loop through the remaining secondLdif entries and check if the DN exists on an entry from firstLdif.
     * If the same DN exists do nothing, else write the entry to the {@link #entriesOnlyInRightLdif} file.
     * Next call the {@link #getDiffUsingDN(java.util.Set, java.util.Set, java.io.File, java.lang.String) } 
     * method to print out modifications necessary to make the entry from firstLdif match the entry from secondLdif.
     * Next remove all entries from firstLdif that are exactly the same as those in secondLdif.
     * Next call the {@link #getDiffUsingDN(java.util.Set, java.util.Set, java.io.File, java.lang.String) } 
     * method to print out modifications necessary to make the entry from secondLdif match the entry from firstLdif.
     * Loop through the remaining firstLdif entries and check if the DN exists on an entry from secondLdif.
     * If the same DN exists do nothing, else write the entry to the {@link #entriesOnlyInLeftLdif} file.
     * 
     * @param firstLdif
     * @param secondLdif
     * @throws IOException 
     */
    private void getMatchUsingDN(Set<Entry> firstLdif, Set<Entry> secondLdif) throws IOException {
            //Entries from the rightLdif that differ or don't exist in leftLdif file
            Set<Entry> difference = new HashSet<>(secondLdif);
            difference.removeAll(firstLdif);//Remove all entries from difference that exist in the firstLdif file
         
            //Create diff file that will show the modifications that are necessary to perform on an entry from the LEFT file to be the same as the entry from the RIGHT file
            String comment = "For the entry from the FIRST LDIF file to match the entry from the SECOND LDIF file the following modifications must be made to the entry from the FIRST LDIF file.";
            getDiffUsingDN(firstLdif, difference, diffFile, comment);
            //Write the entries from rightLdif that differ in some way from leftLdif
            for (Entry e : difference) {
                

                //Get unique entries from the rightLdif file based on DN - no entry with the same DN exist in leftLdif
                String dn = e.getDN();
                boolean unique = true;
                for (Entry entryFromLeft : firstLdif) {
                    if (entryFromLeft.getDN().equals(dn)) {
                        unique = false;
                        writer_diffLdif.writeEntry(e);//Entry exists in both files but differs
                        break;
                    }
                }
                if (unique) {
                    writer_entriesOnlyInRightLdif.writeEntry(e);//Entry only exists in rightLdif
                }

            }
            
            
            //Entries from the leftLdif file that differ or don't exist in the rightLdif file
            firstLdif.removeAll(secondLdif);//Remove all entries from firstLdif that are the same in as the entries in secondLdif
             
            //Create diff file that will show the modifications that are necessary to perform on an entry from the RIGHT file to be the same as the entry from the LEFT file
            comment = "For the entry from the SECOND LDIF file to match the entry from the FIRST LDIF file the following modifications must be made to the entry from the SECOND LDIF file.";
            getDiffUsingDN(secondLdif, firstLdif, new File(diffFile.getParentFile(), fileNameDate + "-reverse-change_records.txt"), comment);
            
            
            for (Entry e : firstLdif) {
                //Get unique entries from the leftLdif file based on DN - no entry with the same DN doesn't exist in rightLdif
                String dn = e.getDN();
                boolean unique = true;
                for (Entry entryFromRight : secondLdif) {
                    if (entryFromRight.getDN().equals(dn)) {
                        unique = false;
                        break;
                    }
                }
                if (unique) {
                    writer_entriesOnlyInLeftLdif.writeEntry(e);//Entry only exits in leftLdif
                }

            }
    }

}
