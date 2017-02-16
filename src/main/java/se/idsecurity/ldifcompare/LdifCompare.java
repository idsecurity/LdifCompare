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
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
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
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.time.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compares two LDIF files and writes the differences to a set of files
 * @author almu
 * 
 */
public class LdifCompare {
    private final static Logger logger = LoggerFactory.getLogger(LdifCompare.class);
    private final int SETSIZE = 100000;
    private final File leftLdif;
    private final File rightLdif;
    private final File entriesThatDiffOrDontExistsInLeftLdif;
    private final File diffFile;
    private final File entriesOnlyInLeftLdif;
    private final File entriesOnlyInRightLdif;
    
    
    /**
     * Contains entries that are for some reason missing the attribute used for matching
     * @since 1.3
     */
    private final File entriesMissingMatchingAttribute;
    
    /**
     * Contains entries that should be deleted because they are not in the "left" file
     * @see LdifCompare#generateDeleteLdifForMissingEntries
     * @since 1.3
     */
    private final File entriesToDeleteInRightFile;
    
    private LDIFReader reader_leftLdif;
    private LDIFReader reader_rightLdif;
    
    private LDIFWriter writer_entriesOnlyInLeftLdif;
    private LDIFWriter writer_entriesOnlyInRightLdif;
    
    /**
     * @see LdifCompare#generateDeleteLdifForMissingEntries
     * @since 1.3
     */
    private LDIFWriter writer_changeTypeDelete = null;
    
    private final List<String> attributesToIgnoreWhenComparing;
    
    /**
     * Used for executing our Runnable objects
     * @since 1.2
     */
    private final ExecutorService exec = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    /**
     * Used for notification when the LDIF files have been read since each file
     * is read by its own thread.
     *
     * @since 1.2
     */
    private final CountDownLatch fileReadCdl = new CountDownLatch(2);
    /**
     * Used for notification when the output files have been written so that we
     * can close them since each file is written in its own thread.
     * 2 are used when comparing using DN, 4 when comparing using 
     * attribute matching
     * 
     * @since 1.2
     */
    private final CountDownLatch fileWriteCdl = new CountDownLatch(4);
    
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
     * Should we generate an LDIF file containing DELETE operations for entries
     * that exist in the "right" LDIF file but are missing from the "left" file?
     */
    private boolean generateDeleteLdifForMissingEntries = false;
    
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
        
        if (this.matchingAttributeNames.isPresent()) {
            this.entriesMissingMatchingAttribute = new File(outputDirectory, fileNameDate +  "-missing-matching-attribute.txt");
        } else {
            this.entriesMissingMatchingAttribute = null;
        }
        
        this.entriesToDeleteInRightFile = new File(outputDirectory, fileNameDate + "-changetype-delete-" + rightLdif.getName());
        
        for (String s : attributesToIgnoreWhenComparing) {
            logger.info("Attribute to ignore when comparing: {}", s);
        }
    }
    
    /**
     * Call this method to start the entire comparison process
     * @throws IOException 
     * @throws java.lang.InterruptedException 
     */
    public void start() throws IOException, InterruptedException {
        reader_leftLdif = new LDIFReader(leftLdif);
        reader_rightLdif = new LDIFReader(rightLdif);
        
        LDIFWriter.setCommentAboutBase64EncodedValues(true);//New in SDK 3.2.0
        writer_entriesOnlyInLeftLdif = new LDIFWriter(entriesOnlyInLeftLdif);
        writer_entriesOnlyInRightLdif = new LDIFWriter(entriesOnlyInRightLdif);
        
        try {
            logger.info("Write comments to {}", entriesThatDiffOrDontExistsInLeftLdif.getPath());
           
            logger.info("Write comments to {}", entriesOnlyInLeftLdif.getPath());
            writer_entriesOnlyInLeftLdif.writeVersionHeader();
            writer_entriesOnlyInLeftLdif.writeComment("Applicable only when matching using DN!", false, false);
            writer_entriesOnlyInLeftLdif.writeComment("This file contain entries that only exist in " + leftLdif.getName() + ", i.e. they are missing for some reason in " + rightLdif.getName() + " or have been renamed/moved and have a different DN.", false, true);
            
            logger.info("Write comments to {}", entriesOnlyInRightLdif.getPath());
            writer_entriesOnlyInRightLdif.writeVersionHeader();
            writer_entriesOnlyInRightLdif.writeComment("Applicable only when matching using DN!", false, false);
            writer_entriesOnlyInRightLdif.writeComment("This file contain entries that only exist in " + rightLdif.getName() + ", i.e. they are missing for some reason in " + leftLdif.getName() + " or have been renamed/moved and have a different DN.", false, true);

            Set<Entry> entriesFromLeftFile = new HashSet<>(SETSIZE);
           
            /**
             * Reads the "left" file in its own thread.
             * @since 1.2
            */
            Runnable leftRunnable = () -> {
                StopWatch sw = new StopWatch();
                sw.start();
                logger.info("Reading file 1: {}", leftLdif.getPath());
                Entry entry = null;
                while (true) {
                    
                    try {
                        entry = reader_leftLdif.readEntry();
                    } catch (LDIFException | IOException e) {
                        logger.error("Exception occured", e);
                    }

                    if (entry == null) {
                        break;
                    }

                    entry = removeIgnoredAttributesFromEntry(entry);
                    entriesFromLeftFile.add(entry);
                    
                   
                }
                sw.stop();
                logger.info("Reading file 1: {} took {}", leftLdif.getPath(), sw.toString());
                fileReadCdl.countDown();
            };
            
            exec.execute(leftRunnable);
            
            
            Set<Entry> entriesFromRightFile = new HashSet<>(SETSIZE);
            
            /**
             * Reads the "right" file in its own thread.
             * @since 1.2
             */
            Runnable rightRunnable = () -> {
                StopWatch sw = new StopWatch();
                sw.start();
                logger.info("Reading file 2: {}", rightLdif.getPath());
                Entry entry = null;
                while (true) {
                    
                    try {
                        entry = reader_rightLdif.readEntry();
                    } catch (LDIFException | IOException e) {
                        logger.error("Exception occured", e);
                    }

                    if (entry == null) {
                        break;
                    }
                    entry = removeIgnoredAttributesFromEntry(entry);
                    entriesFromRightFile.add(entry);
                    
                }
                sw.stop();
                logger.info("Reading file 2: {} took {}", rightLdif.getPath(), sw.toString());
                fileReadCdl.countDown();
            };
            
            exec.execute(rightRunnable);
            
            try {
                fileReadCdl.await();//Wait for the file reads to complete
            } catch (InterruptedException e) {
                logger.error("Thread interrupted", e);
                throw e;
            }

            //If matchingAttributeNames is available then will do a matching using attribute values instead of DN
            if (matchingAttributeNames.isPresent()) {
                logger.info("Will perform diff matching using attributes. " + leftLdif.getName() + ":" + matchingAttributeNames.get().getLeft() + ", " + rightLdif.getName() + ":" + matchingAttributeNames.get().getRight());
                
                //-change_records.txt
                Runnable changeRecords = () -> {
                    logger.info("Creating change records file");
                    StopWatch sw = new StopWatch();
                    sw.start();
                    try {
                        getDiffUsingMatchingAttributes(entriesFromLeftFile, entriesFromRightFile, matchingAttributeNames.get().getLeft(), matchingAttributeNames.get().getRight(), matchingAttributeNames.get(), diffFile, "Matching entries in the FIRST LDIF file using the attribute '" + matchingAttributeNames.get().getRight() + "' from the SECOND LDIF file and displaying modifications that must be made to the entry in the FIRST LDIF file to match the entry from the SECOND LDIF file.");
                    } catch (FileNotFoundException e) {
                        logger.error("Exception creating change records file", e);
                    } finally {
                        sw.stop();
                        logger.info("Creating change records file took {}", sw.toString());
                        fileWriteCdl.countDown();
                    }
 
                };
                exec.execute(changeRecords);
                
                
                //-reverse-change_records.txt
                Runnable reverseChangeRecords = () -> {
                    logger.info("Creating reverse change records file");
                    StopWatch sw = new StopWatch();
                    sw.start();
                    try {
                        getDiffUsingMatchingAttributes(entriesFromRightFile, entriesFromLeftFile, matchingAttributeNames.get().getRight(), matchingAttributeNames.get().getLeft(), matchingAttributeNames.get(), new File(diffFile.getParentFile(), fileNameDate + "-reverse-change_records.txt"), "Matching entries in the SECOND LDIF file using the attribute '" + matchingAttributeNames.get().getLeft() + "' from the FIRST LDIF file and displaying modifications that must be made to the entry in the SECOND LDIF file to match the entry from the FIRST LDIF file.");
                    } catch (FileNotFoundException e) {
                        logger.error("Exception creating reverse change records file", e);
                    } finally {
                        sw.stop();
                        logger.info("Creating reverse change records file took {}", sw.toString());
                        fileWriteCdl.countDown();
                    }
                };
                exec.execute(reverseChangeRecords);
                
                
                File nonMatchingTxt = new File(diffFile.getParentFile(), fileNameDate + "-no-match.txt");
                File nonMatchingLdif = new File(nonMatchingTxt.getParent(), fileNameDate + "-no-match.ldif");
                Runnable nonMatching = () -> {
                    logger.info("Creating non-matching file");
                    StopWatch sw = new StopWatch();
                    sw.start();
                    try {
                        getNonMatchingEntriesUsingMatchingAttributes2(entriesFromLeftFile, entriesFromRightFile, matchingAttributeNames.get(), nonMatchingTxt, nonMatchingLdif);
                    } catch (IOException e) {
                        logger.error("Exception creating non-matching file", e);
                    } finally {
                        sw.stop();
                        logger.info("Creating non-matching file took {}", sw.toString());
                        fileWriteCdl.countDown();
                    }
                };
                exec.execute(nonMatching);
                
                
                File reverseNonMatchingTxt = new File(diffFile.getParentFile(), fileNameDate + "-reverse-no-match.txt");
                File reverseNonMatchingLdif = new File(reverseNonMatchingTxt.getParentFile(), fileNameDate + "-reverse-no-match.ldif");
                Runnable reverseNonMatching = () -> {
                    logger.info("Creating reverse non-matching file");
                    StopWatch sw = new StopWatch();
                    sw.start();
                    try {
                        getReverseNonMatchingEntriesUsingMatchingAttributes2(entriesFromLeftFile, entriesFromRightFile, matchingAttributeNames.get(), reverseNonMatchingTxt, reverseNonMatchingLdif);
                    } catch (IOException e) {
                        logger.error("Exception creating reverse non-matching file", e);
                    } finally {
                        sw.stop();
                        logger.info("Creating reverse non-matching file took {}", sw.toString());
                        fileWriteCdl.countDown();
                    }
                };
                exec.execute(reverseNonMatching);
                
                
                
            } else {
                //Write the change records for entries that have the same DN but differ in some way
                logger.info("Will perform diff matching using DN");
                getMatchUsingDN(entriesFromLeftFile, entriesFromRightFile);
                //Count down two times because we only use two countdown latches
                //when comparing using DN
                fileWriteCdl.countDown();
                fileWriteCdl.countDown();
            }

            //Wait for the file writes to complete before closing the files in the finally block
            fileWriteCdl.await();
            
        } catch (IOException e) {
            logger.error("Exception occured", e);
        } finally {
            
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
            try {
                if (writer_changeTypeDelete != null) {
                    writer_changeTypeDelete.close();
                }
            } catch (IOException close) {
                logger.error("Error closing writer_changeTypeDelete", close);
            }
            
            logger.info("Shut down the ExecutorService");
            exec.shutdown();
        }
        
    }
    
    /**
     * Compare LDIF entries using DN, if the DN is the same in both entries then the entries should be compared
     * @param source Entries from the "left" file
     * @param target Entries from the "right" file
     * @param diffFile Write results to this file
     * @param comment Comment to write to the file
     * @throws FileNotFoundException 
     * @since 1.2
     */
    private void getDiffUsingDN(Set<Entry> source, Set<Entry> target, File diffFile, String comment) throws FileNotFoundException { 
        StopWatch sw = new StopWatch();
        sw.start();
        
        ConcurrentMap<String, Entry> collect = source.parallelStream().collect(Collectors.toConcurrentMap(Entry::getDN, Function.identity()));
        sw.stop();
        logger.info("Set -> ConcurrentMap: " + sw.toString());
        sw.reset();
        
        
        try (PrintWriter writer = new PrintWriter(diffFile)) {
            
            writer.println(comment);
            
            sw.start();
            for (Entry targetEntry : target) {
                String dn = targetEntry.getDN();
                Entry sEntry = collect.get(dn);
                if (sEntry != null) {
                    writer.println();
                    writer.println(dn);
                    List<Modification> diff = Entry.diff(sEntry, targetEntry, false);
                    for (Modification mod : diff) {
                            writer.println(mod);
                    }
                }
                
            }
        }
            sw.stop();
            logger.info("Time taken to loop inside getDiffUsingDN: " + sw.toString());
       
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
        StopWatch sw = new StopWatch();
        sw.start();
        
        
        ConcurrentMap<String, Entry> firstMap = firstLdif.
                parallelStream().
                filter(EntryPredicates.hasAttribute(attributeNameFirst)).
                collect(Collectors.toConcurrentMap(e -> e.getAttributeValue(attributeNameFirst), Function.identity()));

        sw.stop();
        logger.info("Convert firstLdif set -> ConcurrentMap: " + sw.toString());
        sw.reset();
        
        PrintWriter missingMatchingAttributeWriter = new PrintWriter(entriesMissingMatchingAttribute);//Write entries that are missing the matching attribute

        try (PrintWriter writer = new PrintWriter(diffFile)) {
            
            writer.println(comment);
            
            sw.start();
            for (Entry secondEntry : secondLdif) {
                
                String attributeValueSecond = secondEntry.getAttributeValue(attributeNameSecond);
                
                if (attributeValueSecond == null) {
                    logger.error("attributeValueSecond is null for secondEntry: {}", secondEntry.getDN());
                    missingMatchingAttributeWriter.println("attributeValueSecond is null for secondEntry: " + secondEntry.getDN());
                    continue;
                } 
                
                Entry firstEntry = firstMap.get(attributeValueSecond);
                if (firstEntry != null) {
                    writer.println();
                    writer.println("Matched '" + firstEntry.getDN() + "' using value '" + attributeValueSecond + "' with '" + secondEntry.getDN() + "'");
                    //writer.println(dn);
                    List<Modification> diff = Entry.diff(firstEntry, secondEntry, false);
                    
                    if (diff.isEmpty()) {
                        writer.println("NO DIFF");
                    } else {
                        diff.stream().forEach(mod -> writer.println(mod));
                    }
         
                }
                
            }
            
            missingMatchingAttributeWriter.close();
            sw.stop();
            logger.info("Time taken to loop inside getDiffUsingMatchingAttributes: " + sw.toString());
      

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
    private void getNonMatchingEntriesUsingMatchingAttributes1(Set<Entry> firstLdif, Set<Entry> secondLdif, MatchingAttributeNames attributeName, File diffFile, File ldifFile) throws IOException {
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
     * For each entry in the <b>left</b> file try to find a match in the <b>right</b> file.
     * @param firstLdif Entries from the "left" file
     * @param secondLdif Entries from the "right" file
     * @param attributeName Attribute to use for matching
     * @param diffFile Write results to this file
     * @param ldifFile Write LDIF entries to this file
     * @throws IOException 
     */
    private void getNonMatchingEntriesUsingMatchingAttributes2(Set<Entry> firstLdif, Set<Entry> secondLdif, MatchingAttributeNames attributeName, File diffFile, File ldifFile) throws IOException {
        LDIFWriter ldifWriter = new LDIFWriter(ldifFile);
        ldifWriter.writeVersionHeader();

        PrintWriter writer = new PrintWriter(diffFile);
        writer.println("Unable to match entries in the FIRST LDIF file using the attribute '" + attributeName.getRight() + "' from the SECOND LDIF file.");

         ConcurrentMap<String, Entry> map = secondLdif.
                parallelStream().
                filter(EntryPredicates.hasAttribute(attributeName.getRight())).
                collect(Collectors.toConcurrentMap(e -> e.getAttributeValue(attributeName.getRight()), Function.identity()));
        
        
        
        firstLdif.stream().forEach((Entry first) -> {
            String attrValue = first.getAttributeValue(attributeName.getLeft());
            if (attrValue != null && map.containsKey(attrValue)) {
                //logger.info("Found reverse match for {} : {}", second.getDN(), map.get(attrValue));
            } else {
                writer.println();
                writer.println("No match found '" + first.getDN() + "' using value '" + first.getAttributeValue(attributeName.getLeft()) + "'");
                try {

                    ldifWriter.writeEntry(first, "No match found '" + first.getDN() + "' using value '" + first.getAttributeValue(attributeName.getLeft()) + "'");
                    
                    if (generateDeleteLdifForMissingEntries) {
                        writeChangetypeDeleteRecord(first.getDN());
                    }
                    
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
    private void getReverseNonMatchingEntriesUsingMatchingAttributes1(Set<Entry> firstLdif, Set<Entry> secondLdif, MatchingAttributeNames attributeName, File diffFile, File ldifFile) throws IOException {
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
     * Retrieves entries that we are unable to match using a matching attribute and writes those entries to output files.
     * For each entry in the <b>right</b> file try to find a match in the <b>left</b> file.
     * @param firstLdif Entries from the "left" file
     * @param secondLdif Entries from the "right" file
     * @param attributeName Attribute to use for matching
     * @param diffFile Write results to this file
     * @param ldifFile Write LDIF entries to this file
     * @throws IOException 
     */
    private void getReverseNonMatchingEntriesUsingMatchingAttributes2(Set<Entry> firstLdif, Set<Entry> secondLdif, MatchingAttributeNames attributeName, File diffFile, File ldifFile) throws IOException {
    
        LDIFWriter ldifWriter = new LDIFWriter(ldifFile);
        ldifWriter.writeVersionHeader();
        PrintWriter writer = new PrintWriter(diffFile);
        writer.println("Unable to match entries in the SECOND LDIF file using the attribute '" + attributeName.getLeft() + "' from the FIRST LDIF file.");

        ConcurrentMap<String, Entry> map = firstLdif.
                parallelStream().
                filter(EntryPredicates.hasAttribute(attributeName.getLeft())).
                collect(Collectors.toConcurrentMap(e -> e.getAttributeValue(attributeName.getLeft()), Function.identity()));
        
        
        
        secondLdif.stream().forEach((Entry second) -> {
            String attrValue = second.getAttributeValue(attributeName.getRight());
            if (attrValue != null && map.containsKey(attrValue)) {
                //logger.info("Found reverse match for {} : {}", second.getDN(), map.get(attrValue));
            } else {
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
            Set<Entry> secondLdifFirstLdifDiff = new HashSet<>(secondLdif);
            secondLdifFirstLdifDiff.removeAll(firstLdif);//Remove all entries that exist in the firstLdif file
         
            //Create diff file that will show the modifications that are necessary to perform on an entry from the LEFT file to be the same as the entry from the RIGHT file
            String comment = "For the entry from the FIRST LDIF file to match the entry from the SECOND LDIF file the following modifications must be made to the entry from the FIRST LDIF file.";
            getDiffUsingDN(firstLdif, secondLdifFirstLdifDiff, diffFile, comment);
            //Write the entries from rightLdif that differ in some way from leftLdif
            getUniqueEntriesUsingDN(secondLdif, firstLdif, writer_entriesOnlyInRightLdif, true);
            
            //Entries from the leftLdif file that differ or don't exist in the rightLdif file
            Set<Entry> firstLdifSecondLdifDiff = new HashSet<>(firstLdif);//Remove all entries from firstLdif that are the same in as the entries in secondLdif
            firstLdifSecondLdifDiff.removeAll(secondLdif);
            
            //Create diff file that will show the modifications that are necessary to perform on an entry from the RIGHT file to be the same as the entry from the LEFT file
            comment = "For the entry from the SECOND LDIF file to match the entry from the FIRST LDIF file the following modifications must be made to the entry from the SECOND LDIF file.";
            getDiffUsingDN(secondLdif, firstLdifSecondLdifDiff, new File(diffFile.getParentFile(), fileNameDate + "-reverse-change_records.txt"), comment);
            

            getUniqueEntriesUsingDN(firstLdif, secondLdif, writer_entriesOnlyInLeftLdif, false);


    }

    /**
     * Put all entries from target into a map and then loop through all entries in
     * source, check if the entry from source exists in the target map based on
     * DN, if it doesn't write it to a file.
     * @param source
     * @param target
     * @param ldifWriterUnique 
     */
    private void getUniqueEntriesUsingDN(Set<Entry> source, Set<Entry> target, LDIFWriter ldifWriterUnique, boolean sourceIsRightFile) {
        Runnable r = () -> {
            StopWatch sw = new StopWatch();
            sw.start();
            ConcurrentMap<String, Entry> targetMap = target.parallelStream().collect(Collectors.toConcurrentMap(Entry::getDN, Function.identity()));
            

            for (Entry e : source) {
               
                String dn = e.getDN();
                if (!targetMap.containsKey(dn)) {
                    try {
                        ldifWriterUnique.writeEntry(e);//Entry only exists in rightLdif


                        if (sourceIsRightFile && generateDeleteLdifForMissingEntries) {
                            writeChangetypeDeleteRecord(dn);
                        }

                        
                    } catch (IOException ex) {
                        logger.error("Error writing to LDIF file", ex);
                    }
                }
            }
            fileWriteCdl.countDown();
        
            sw.stop();
            logger.info("Time taken to process getUniqueEntriesUsingDN(): " + sw.toString());
            sw.reset();
        };
        
        exec.execute(r);

    }

    /**
     * Should we generate an LDIF containing DELETE operations for entries that
     * are missing from the "left" LDIF file but that exist in the "right" file?
     * @return true if the file should be generated, false otherwise
     */
    protected boolean generateDeleteLdifForMissingEntries() {
        return generateDeleteLdifForMissingEntries;
    }

    /**
     * Set to true if you want to generate an LDIF containing DELETE operations
     * for entries that are missing from the "left" LDIF file but that exist in
     * the "right" file
     * @param generateDeleteLdifForMissingEntries 
     * @since 1.3
     */
    protected void setGenerateDeleteLdifForMissingEntries(boolean generateDeleteLdifForMissingEntries) {
        this.generateDeleteLdifForMissingEntries = generateDeleteLdifForMissingEntries;
    }
    
    private void writeChangetypeDeleteRecord(String dn) throws IOException {
        if (writer_changeTypeDelete == null) {
            writer_changeTypeDelete = new LDIFWriter(entriesToDeleteInRightFile);
            writer_changeTypeDelete.writeVersionHeader();
        }
        
        writer_changeTypeDelete.writeChangeRecord(new LDIFDeleteChangeRecord(dn));
    } 
    
    private enum Side {
        LEFT, RIGHT;
    }
}
