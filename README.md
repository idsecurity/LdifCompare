# LDIFCompare

> A tool based on the UnboundID LDAP SDK library that can be used to compare two LDIF files and output the differences.

# Requirements

- Java 8u40 or newer
- UnboundID LDAP SDK
- SLF4J
- Apache Commons Lang

# Instructions

For help run:
`java -jar LDIFCompare-1.0-SNAPSHOT.jar --help`

# Example scenario

Let's say you are about to perform some kind of operation on a couple of thousand 
accounts in an LDAP directory using an automated provision tool and you want to make
sure that you have not caused any unintended consequences by accidently modifying
attributes or objects that are not in the scope of your operation.

- The basic idea is to take a snapshot of the directory before your operation by doing an LDIF export.
- Then you take another snapshot after the operation has taken place by doing another LDIF export.
- Use your favorite diff tool to compare the two LDIF files and figure out why they diff and if the diff is important or not.

LDIFCompare allows you to compare LDIF files and specify which attributes you 
want to ignore when comparing, for example you might not be interested if the 
`logonTime` attribute has changed.

# Concepts

I have chosen to call the file that contains the original pre-operation snapshot for the "left" file and the post-operation snapshot for the "right" file.

Imagine the two LDIF files side by side on your screen.
- The pre-operation file is called the left file.
- The post-operation file is called the right file.

Using a properties file with the property "ignore-attributes" you can specify which attributes to ignore while comparing.
During processing all attributes specified in "ignore-attributes" will be removed from both entries before being compared and before the results are written to files.
For examples see the `doc\ldifcompare.properties` file.

# Output

After processing you will get a number of result files.

It will output five files:
Each file is prefixed with the date and time of the operation in the following format:
yyyy-MM-dd HHmmss

- -change_records.txt, contains the modifications that must be performed on an entry from the "left" file to match the entry from the "right" file.
- -reverse-change_records.txt, contains the the modifications that must be performed on an entry from the "right" file to match the entry from the "left" file.
- -unique-\<left file name>.ldif, contains the entries that only exist in the "left" file.
- -unique-\<right file name>.ldif, contains the entries that only exist in the "right" file. 

# Example usage

Let's say you have two files you want to compare, the original "left" file and the post-operation "right" file.

You would execute the following command to compare them:

`java -jar LDIFCompare-1.0.jar --ldifLeft ./left.ldif --ldifRight ./right.ldif --output /path/to/outputdirectory --properties ./ldifcompare.properties`

The `ldifcompare.properties` file must contains one property called `ignore-attributes=attr1,attr2`.
The values of the property are the names of the attributes to ignore when comparing, separated with a comma.
For an example see the `doc/ldifcompare.properties` file.
In the example above you would replace attr1,attr2 with the actual attribute names.

During a compare the DN is used to match entries between two LDIF-files, if an entry is moved, deleted or renamed then you won't get a match.

If you want to use an attribute instead of the DN to match two entries then you can do that by specifying the following property in the properties file:
*match-attribute=nameOfAttribute*

# Limitations

Handles only LDIF files containing content records or add records. Modify records and other changetypes are not supported.

# Changelog

 \+ Added feature            
 \* Improved/changed feature 
 \- Bug fixed/refactoring    
 ! security bug fix         
 ~ partial implementation   

v1.2

\* Removed the LDIF file that contained entire entries that differed in some way but without any information on what actually differed.

\* Introduced threading and performance optimizations, for example comparing two LDIF files, 463 MB and 314 MB using the DN as key previously took ~20 minutes. Now it takes ~40 seconds. An improvement by a factor of 30.

\+ Outputs the time to run each operation to stdout.



# License

[GPL v3.0](http://www.gnu.org/licenses/gpl-3.0.txt)
