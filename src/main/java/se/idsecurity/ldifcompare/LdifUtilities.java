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

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.FileArgument;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author almu
 */
public class LdifUtilities extends CommandLineTool {
    
    private ArgumentParser parser;
    
    private final static Logger log = LoggerFactory.getLogger(LdifUtilities.class);

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        final ResultCode resultCode = main(args, System.out, System.err);
        if (resultCode != ResultCode.SUCCESS) {
            System.exit(resultCode.intValue());
        }
    }
    
    /**
   * Parse the provided command line arguments and make the appropriate set of
   * changes.
   *
   * @param  args       The command line arguments provided to this program.
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
  {
    LdifUtilities ldifUtilities = new LdifUtilities(outStream, errStream);
    return ldifUtilities.runTool(args);
  }

      /**
   * Creates a new instance of this tool.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   */
    public LdifUtilities(OutputStream outStream, OutputStream errStream) {
        super(outStream, errStream);
        Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler());
    }
  
    

    @Override
    public String getToolName() {
        return "LDIF Utilities";
    }

    @Override
    public String getToolDescription() {
        return "Compares LDIF files";
    }

    @Override
    public void addToolArguments(ArgumentParser parser) throws ArgumentException {
        FileArgument leftLdifFile = new FileArgument('l', "ldifLeft", true, 1, "c:/path/original.ldif", "LDIF file with before state", false, true, true, false);
        FileArgument rightLdifFile = new FileArgument('r', "ldifRight", true, 1, "c:/path/aftermigration.ldif", "LDIF file with after state", false, true, true, false);
        FileArgument outputDirectory = new FileArgument('o', "output", false, 1, "c:/path/outputDirectory", "Output directory that will contain the diff files", true, false, false, true);
        
        FileArgument propertiesFile = new FileArgument(null, "properties", true, 1, "c:/path/ldifcompare.properties", "Properties file that governs the behavior of the comparison", false, true, true, false);
     
        parser.addArgument(leftLdifFile);
        parser.addArgument(rightLdifFile);
        parser.addArgument(outputDirectory);
        
        parser.addArgument(propertiesFile);
        
        this.parser = parser;
    }
    
    @Override
    public ResultCode doToolProcessing() {
        
        File leftLdif = ((FileArgument)parser.getNamedArgument("ldifLeft")).getValue();
        File rightLdif = ((FileArgument)parser.getNamedArgument("ldifRight")).getValue();
        File outputDirectory = ((FileArgument)parser.getNamedArgument("output")).getValue();
        
        if (outputDirectory == null) {
              Path cwd = Paths.get("");
              outputDirectory = cwd.toFile();
        }
        
        
        File propertyFile = ((FileArgument)parser.getNamedArgument("properties")).getValue();
        
        log.error("Load properties from: " + propertyFile.getPath());
        
        LoadProperties property = new LoadProperties(propertyFile);
        
        try {
            property.initialize();
        } catch (IOException e) {
            log.error("Could not load property file: {}", propertyFile.getPath(), e);
            return ResultCode.PARAM_ERROR;
        }
        
        MatchingAttributeNames man = property.getMatchingAttributeNames();
        
        LdifCompare compare = new LdifCompare(leftLdif, rightLdif, outputDirectory, property.getCommaSeparatedPropertyAsList("ignore-attributes"), man);
        
        try {
            compare.start();
            return ResultCode.SUCCESS;
        } catch (IOException e) {
            log.error("LdifCompare failed", e);
            return ResultCode.LOCAL_ERROR;
        }
        
       
    }
    
    
  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>();

    final String[] args =
    {
      "--ldifLeft", "c:/path/left.ldif",
      "--ldifRight", "c:/path/right.ldif",
      "--output", "c:/path/outputDirectory",
      "--properties", "c:/path/ldifcompare.properties",
  
    };
    final String description =
         "Compares two LDIF files (left and right).\n"
            + "Outputs the entries from the \"right\" file that don't match any"
            + "entries in the \"left\" file to the \"yyyy-MM-dd HH:mm:ss-diff.ldif\" file.\n\n"
            + "Additonally the following files are created:\n"
            + "yyyy-MM-dd HHmmss-change_records.txt\n"
            + "yyyy-MM-dd HHmmss-reverse-change_records.txt\n"
            + "yyyy-MM-dd HHmmss-unique-<ldifLeft file name>\n"
            + "yyyy-MM-dd HHmmss-unique-<ldifRight file name>\n"
            + "The left file would for example contain entries in an original state\n"
            + "and the right file would contain entries after some kind of processing.\n"
            + "The tool would be used for making sure that the processing was correct.\n"
            + "The properties file needs to contain one property: \n"
            + "ignore-attributes=attr1,attr2\n"
            + "I.e. a comma separated list of attributes to ignore when comparing entries.\n"
            + "Attributes that one wants to ignore can be e.g. lastLogon etc.\n\n"
            + "The tool uses the DN to match entries unless the properties file contains the following key/value:\n"
            + "match-attribute=nameOfAttribute";
    examples.put(args, description);

    return examples;
  }
    
  public class UncaughtExceptionHandler implements Thread.UncaughtExceptionHandler {

        @Override
        public void uncaughtException(Thread t, Throwable e) {
            log.error("CAUGHT UNCAUGHTEXCEPTION FROM THREAD: " + t.getName(), e);
        }
      
  }
 
}
