***************************************************************************
*
* README.build.win32
*
* Authors: Alex Burger <alex_b@users.sourceforge.net>
*          
*
***************************************************************************

Introduction
============

This README outlines the steps required to create a binary release for
Windows using Microsoft Visual Studio and the NullSoft installer.

There are four sections:

  Compiling binaries

  Compiling HTMLHelp file

  Combining the binaries and HTMLHelp files

  Bulding a NullSoft installer package

  Bulding an OpenSSL version


Compiling binaries
==================

Requirements
------------

 -Windows NT/2000/XP
 -MSVC++ 6.0 SP5
 -ActivePerl 5.8.2 build 808
 -gnu_regex.exe (0.12) - http://people.delphiforums.com/gjc/gnu_regex.html
 -Platform SDK
 -MSYS / MinGW -or- tar.exe and gzip.exe
 -win32/dist folder from MAIN in CVS


Building the main binaries
--------------------------

Note:  All shell steps are using the Window CMD prompt unless otherwise stated.

Part 1
------

1.  Extract source.  The location will be referenced as (source dir)

2.  Delete c:\usr if it exists and rename Net-SNMP.dll in your %windir% if you 
    have it already (to ensure Perl tests are using the compiled DLL)

3.  Apply any required patches

4.  Remove the example MIB files:  

    Edit win32\net-snmp\agent\mib_module_config.h and change the following lines:

      #define USING_EXAMPLES_UCDDEMOPUBLIC_MODULE 1
      #define USING_EXAMPLES_EXAMPLE_MODULE 1

    to:

      #undef USING_EXAMPLES_UCDDEMOPUBLIC_MODULE
      #undef USING_EXAMPLES_EXAMPLE_MODULE

5.  cd (source dir)\win32

6.  Run build.bat

7.  Set to the following:

    Net-SNMP build and install options
    ==================================
    
    1.  OpenSSL support:      		disabled
    2.  Platform SDK support: 		enabled         ***
    
    3.  Install path:         		c:/usr
    4.  Install after build:  		enabled
    
    5.  Perl modules:         		enabled         ***
    6.  Install perl modules: 		disabled
    
    7.  Quiet build (logged): 		enabled
    8.  Debug mode:           		disabled

    9.  IPv6 transports:      		disabled
    10. winExtDLL agent (requires SDK): disabled

    11. Link type:                      dynamic		***

    12. Install development files   	enabled         ***
    
    F.  Finished - start build
    Q.  Quit - abort build
    
    Select option to set / toggle:

8.  F to start the build and verify everything was built ok

9.  Delete any generated config files from c:\usr\snmp\persist

Part 2 - Compiling winExtDLL
----------------------------

10. Run build.bat and set to the following:

    Net-SNMP build and install options
    ==================================
    
    1. OpenSSL support:      		disabled
    2. Platform SDK support: 		enabled         ***
    
    3. Install path:         		c:/usr
    4. Install after build:  		disabled        ***
    
    5. Perl modules:         		disabled
    6. Install perl modules: 		disabled
    
    7. Quiet build (logged): 		enabled
    8. Debug mode:           		disabled

    9. IPv6 transports:      		disabled
    10. winExtDLL agent (requires SDK): enabled         ***

    11. Link type:                      dynamic		***

    12. Install development files   	disabled
    
    F.  Finished - start build
    Q.  Quit - abort build
    
    Select option to set / toggle:

11. F to start the build and verify everything was built ok

12. Copy the new binary:

    copy bin\release\snmpd.exe c:\usr\bin\snmpd-winExtDLL.exe

13. Test each binary by running each one with -DwinExtDLL.  Make sure only the
    winExtDLL version has debug output.

14. Delete any generated config files from c:\usr\snmp\persist


Part 3 - Creating the Perl package
----------------------------------

1.  cd (source dir)
    cd perl

2.  nmake ppd

3.  Open an MSYS shell (unless you have tar.exe and gzip.exe)

4.  cd (source dir)
    cd perl

5.  tar cvf NetSNMP.tar blib; gzip --best NetSNMP.tar

6.  Open a Windows command prompt (CMD) and cd (source dir)\perl

7.  ren Bundle-NetSNMP.ppd NetSNMP.ppd

8.  Modify NetSNMP.ppd to look like the following.  Change the 
    VERSION="x,x,x,x" line to the correct values.  Do NOT change 
    * lines in the original file.

<SOFTPKG NAME="NetSNMP" VERSION="5,4,1,0">
    <TITLE>Net-SNMP</TITLE>
    <ABSTRACT>Object Oriented Interface to Net-SNMP</ABSTRACT>
    <AUTHOR></AUTHOR>
    <IMPLEMENTATION>
*        <OS NAME="MSWin32" />
*        <ARCHITECTURE NAME="MSWin32-x86-multi-thread-5.8" />
        <CODEBASE HREF="x86/NetSNMP.tar.gz" />
    </IMPLEMENTATION>
</SOFTPKG>

9.  Copy the win32\dist folder from trunk to the win32 folder of the extracted source.

10. Create base directories:

    md "c:\usr\docs"
    md "c:\usr\perl"
    md "c:\usr\perl\x86"
    md "c:\usr\temp"

12. Copy files:

    cd (source dir)
    copy COPYING "c:\usr\docs"
    copy win32\dist\README.txt "c:\usr"
    copy win32\dist\scripts\net-snmp-perl-test.pl "c:\usr\bin"

    copy perl\NetSNMP.ppd "c:\usr\Perl"
    copy perl\NetSNMP.tar.gz "c:\usr\Perl\x86"

12. Update the BUILD INFORMATION section of c:\usr\README.txt


Compiling HTMLHelp file
=======================

This section outlines the steps required to build a Windows HTML Help file
based on the Net-SNMP man pages, README files, Perldoc documentation etc.

Requirements
------------

 -Linux (or similar) with:
   -man (man page viewer)
   -tidy (HTML tidy - http://tidy.sourceforge.net)
   -Perl
   -perldoc
   -man2html3.0.1.tar.gz (http://search.cpan.org/~ehood/man2html3.0.1/)
    Note:  Most Linux distributions come with man2html as part of the man rpm
           package which is not the same as man2html from man2html3.0.1.tar.gz.
           All that is needed from man2html3.0.1.tar.gz is the man2html script.  
           You do not need to do a complete install (make/make install) but you
           do need to make sure the script is configured correctly by setting the
           man command line switches etc for the OS from inside of the script.

 -Windows with:
   -HTML Help Workshop (Search msdn.microsoft.com for 'html help workshop download')


Convert documents to html
-------------------------

Note:  The following steps are completed using Linux.

Note:  A temporary location of /tmp/net-snmp is used.

1.  Extract Net-SNMP source and cd (source dir)

2.  cd (source dir)

3.  cp perl/SNMP/README README.perl

4.  Remove older copies of converted files:

    rm -R -f /tmp/net-snmp

5.  Build Net-SNMP man pages: 

    ./configure --prefix=c:/usr; make sedscript; cd man;make; cd ..

6.  Install only the man files to /temp/net-snmp:

    cd man; make install prefix=/tmp/net-snmp; cd ..

7.  Go to the scripts folder and make sure all the scripts are executable:

    cd (source dir)
    cd win32/dist/scripts; chmod +x *

8.  Edit these files and make sure the paths are correct in the OPTIONS 
    section.  Also ensure the list of README files and Perl modules 
    are correct in readme2html and poddir2html.

    mandir2html
    readme2html
    poddir2html

    Note:  mandir2html will process ALL man pages in c:\temp\net-snmp while
           readme2html and poddir2html will only process files listed in the
           script.  If new man pages are added or removed, the Table of 
           Contents (toc.hhc) and project file (Net-SNMP.hhp) need to be 
           updated by hand.

9.  Run each script to generate the .html files:

    ./mandir2html; ./readme2html; ./poddir2html

    Note:  There will be many warnings from tidy which can be ignored.

10. Verify each converted file to ensure all the links are correct.  The files
    are located in /tmp/net-snmp/html by default.  In some instances, URLs may be 
    split across two lines such as the Variables link at the bottom of 
    /tmp/net-snmp/html/man8-snmptrapd.8.html.

11. If new man pages are added or removed, the Table of Contents (Net-SNMP.hhc) and
    project file (Net-SNMP.hhp) need to be updated by hand.

12. Convert EXAMPLE.conf.win32 to html:

    ./txt2html ../../EXAMPLE.conf.win32 | tidy > /tmp/net-snmp/html/EXAMPLE.conf.win32.html
    

Build Net-SNMP.chm
------------------

Note:  The following steps are completed using Windows.

Note:  A temporary location of c:\temp\net-snmp is used.

1.  Transfer /tmp/net-snmp/html from Linux to c:\temp\net-snmp\html

2.  Grab the FAQ from the web site, strip out the includes and save as
    c:\temp\net-snmp\html\FAQ.html and run:

    tidy -asxhtml -m c:\temp\net-snmp\html\FAQ.html

3.  Grab the Devloper FAQ from the web site, strip out the includes and save as
    c:\temp\net-snmp\html\Developer_FAQ.html and run:

    tidy -asxhtml -m c:\temp\net-snmp\html\Developer_FAQ.html

4.  Copy the following files to c:\temp\net-snmp\html:

    cd (source dir)
    copy "win32\dist\htmlhelp\Configuration_Overview.html" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\Help_Caveats.html" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\Introduction.html" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\Net-SNMP.hhc" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\Net-SNMP.hhp" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\net-snmp-4.2-800.jpg" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\snmp.conf.win32.html" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\snmpd.conf.win32.html" c:\temp\net-snmp\html\
    copy "win32\dist\htmlhelp\snmptrapd.conf.win32.html" c:\temp\net-snmp\html\

5.  New configuration options may be available in the new release of
    Net-SNMP, so the *.conf.win32.html files should be updated.

    Create a text file with all the configuration options for snmpd and 
    snmptrapd using:

    cd win32\bin\release (folder of *Windows* compiled Net-SNMP)
    snmptrapd -H 2> c:\temp\net-snmp\html\snmptrapd.options
    snmpd -H 2> c:\temp\net-snmp\html\snmpd.options

    Update these files using an HTML editor (Mozilla etc):

    c:\temp\net-snmp\html\snmp.conf.win32.html
    c:\temp\net-snmp\html\snmpd.conf.win32.html
    c:\temp\net-snmp\html\snmptrapd.conf.win32.html
 
    Only add the relevent section to each file from the .options files
    created above, ensure the font is set to fixed width.

    Tidy each file using tidy under Windows (or transfer to Linux and tidy
    using Linux):

    tidy -asxhtml -m c:\temp\net-snmp\html\snmptrapd.conf.win32.html
    tidy -asxhtml -m c:\temp\net-snmp\html\snmpd.conf.win32.html
    tidy -asxhtml -m c:\temp\net-snmp\html\snmp.conf.win32.html

6.  Edit c:\temp\net-snmp\html\Net-SNMP.hhp and update the version for the 
    'Title' variable.

7.  Run HTML Workshop

8.  Open c:\temp\net-snmp\html\Net-SNMP.hhp

9.  Click File - Compile

10. Select 'C:\temp\net-snmp\html\Net-SNMP.hhp' as the filename

11. Click Compile

12. You should now have a c:\temp\net-snmp\html\Net-SNMP.chm file.

13. Launch the file and ensure every content item displays the correct page.


Combining the binaries and HTMLHelp files
=========================================

1.  Copy the HTML Help file to c:\usr\docs:

    copy c:\temp\Net-SNMP\html\Net-SNMP.chm c:\usr\docs\


Bulding a NullSoft installer package
====================================

Requirements
------------

 -Windows
 -Nullsoft Scriptable Install System 2.0 - http://nsis.sourceforge.net/home/

1.  Complete the three sections above:  'Compiling binaries', 'Compiling 
    HTMLHelp file' and 'Combining the binaries and HTMLHelp files'.  Net-SNMP
    should be located in c:\usr.

2.  Copy the following files to c:\usr:

    cd (source dir)
    copy win32\dist\installer\SetEnVar.nsi c:\usr\
    copy win32\dist\installer\net-snmp.nsi c:\usr\
    copy win32\dist\installer\Add2Path.nsi c:\usr\
    copy win32\dist\installer\net-snmp-header1.bmp c:\usr\

3.  Create the following empty files:

    echo . > c:\usr\registeragent.bat
    echo . > c:\usr\unregisteragent.bat
    echo . > c:\usr\registertrapd.bat
    echo . > c:\usr\unregistertrapd.bat
    echo . > c:\usr\etc\snmp\snmp.conf

4.  Edit the following variables in c:\usr\net-snmp.nsi:

    PRODUCT_MAJ_VERSION
    PRODUCT_MIN_VERSION
    PRODUCT_REVISION
    PRODUCT_EXE_VERSION

    For example, for 5.1.2:

    PRODUCT_MAJ_VERSION "5"
    PRODUCT_MIN_VERSION "1"
    PRODUCT_REVISION "2"
    PRODUCT_EXE_VERSION "1"

    The generated filename would be: net-snmp-5.1.2-1.win32.exe

    PRODUCT_EXE_VERSION is usually 1 unless the binary package is re-released
    due to packaging issues.  For pre releases, include the pre-release version 
    in PRODUCT_REVISION.   For example, for 5.1.2 pre2 use:

    PRODUCT_MAJ_VERSION "5"
    PRODUCT_MIN_VERSION "1"
    PRODUCT_REVISION "2.pre2"
    PRODUCT_EXE_VERSION "1"

    This will ensure the version number is visible during installation.

    The generated filename would be: net-snmp-5.1.2.pre2-1.win32.exe

5.  Launch the 'Nullsoft Install System (NSIS 2.0)'

6.  Select 'MakeNSISW (compiler interface)'

7.  Click File - Load Script

8.  Select c:\usr\net-snmp.nsi

9.  You should now have a c:\usr\Net-SNMP-x.x.x-x.exe binary installer 
    package

10. Test the package

11. Compare the directory contents of the compiled folder with the installed
    folder to ensure there are no missing MIB files etc.  Modify net-snmp.nsi
    and rebuild if required.

12. Create a .zip file of c:\usr for archive purposes.


Bulding an OpenSSL version
==========================

Requirements
------------

 -OpenSSL binary from http://www.slproweb.com/products/Win32OpenSSL.html

1.  Install the OpenSSL binary, header and library files as explained in 
    'Using a pre-compiled version' of the 'Microsoft Visual C++ - Building with 
    OpenSSL' section of README.win32.

2.  Move c:\usr c:\usr.temp

3.  Re-build the binary by following the steps in the section 'Building the 
    main binaries' except enable OpenSSL (both regular and WinExtDLL).  Also 
    follow the Perl steps to create a new tar file etc.

4.  Copy contents of c:\usr to c:\usr.temp

5.  Delete c:\usr

6.  Move c:\usr.temp c:\usr

7.  Update the BUILD INFORMATION section of c:\usr\README.txt to include the SSL 
    info and the filename.

8.  Update the version stamp in c:\usr\net-snmp.nsi to include -ssl.  Example:

    For example, for 5.3.0:

    PRODUCT_MAJ_VERSION "5"
    PRODUCT_MIN_VERSION "3"
    PRODUCT_REVISION "0-ssl"
    PRODUCT_EXE_VERSION "1"

    The generated filename would be: net-snmp-5.3.0-ssl-1.win32.exe

9.  Also in c:\usr\net-snmp.nsi, change:

    !define OPENSSL_REQUIRED "0"

    to

    !define OPENSSL_REQUIRED "1"

10. Launch the 'Nullsoft Install System (NSIS 2.0)'

11. Select 'MakeNSISW (compiler interface)'

12. Click File - Load Script

13. Select c:\usr\net-snmp.nsi

14. You should now have a c:\usr\Net-SNMP-x.x.x-x.exe binary installer 
    package

15. Test the package

16. Compare the directory contents of the compiled folder with the installed
    folder to ensure there are no missing MIB files etc.  Modify net-snmp.nsi
    and rebuild if required.

17. Create a .zip file of c:\usr for archive purposes.

