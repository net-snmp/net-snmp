***************************************************************************
*
* README.build.win32
*
* Author: Alex Burger <alex_b@users.sourceforge.net>
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


Compiling binaries
==================

Requirements
------------

32-bit binary:

 -Windows XP 32-bit SP2 or higher
 -Microsoft Visual Studio 2008 SP1 with Platform SDK and latest updates from Microsoft
  including updates to the redistributable components
 -Perl 5.10 or later
 -MSYS / MinGW -or- tar.exe and gzip.exe
 -win32/dist folder from MAIN in CVS
 -OpenSSL binary and library files from http://www.slproweb.com/products/Win32OpenSSL.html

64-bit binary:

 -Windows 7 64-bit
 -Microsoft Visual Studio 2008 SP1 with Platform SDK and latest updates from Microsoft
  including updates to the redistributable components.  Also need are the 64-bit compiler options.
 -Perl 5.10 or later (64-bit)
 -MSYS / MinGW -or- tar.exe and gzip.exe
 -win32/dist folder from MAIN in CVS
 -OpenSSL 64-bit binary and library files from http://www.slproweb.com/products/Win32OpenSSL.html


Building the main binaries
--------------------------

Note:  All shell steps are using the Window CMD prompt unless otherwise stated.

Part 1
------

1.  Install pre-requisites:

    MSVC 2008:
      Include the Platform SDK and for 64-bit, make sure the 64-bit compiler is installed
      (not included by default).

      Latest updates from Microsoft to ensure the redistributable DLLs have the latest
      security fixes.

    Perl:
      For 64-bit, make sure you install the 64-bit version otherwise compiling will fail.

    MSYS / MinGW:
      Needed for tar command in build-binary.bat/pl.  

    OpenSSL:
      Install the OpenSSL binary, header and library files as explained in 
      'Using a pre-compiled version' of the 'Microsoft Visual C++ - Building with 
      OpenSSL' section of README.win32.  For 64-bit, make sure you install the 64-bit 
      version otherwise compiling will fail.

2.  Extract source.  The location will be referenced as (source dir)

3.  Delete c:\usr if it exists.

4.  Apply any required patches

5.  cd (source dir)\win32\dist

6.  Run build-binary.bat.  

    If c:\usr already exists, it will stop with an error.

    If %windir%\system32\netsnmp.dll exists, it will ask if it can be deleted.  Answer yes.

7.  At a high level, the following will be completed:

    a)  Get package version from Unix configure script for use in the Perl module and NSIS
        installer package.
    b)  Build the applications and Perl modules with OpenSSL enabled and winExtDLL disabled
    c)  Build the applications and Perl modules with OpenSSL enabled and winExtDLL enabled
    d)  Build the applications and Perl modules with OpenSSL disabled and winExtDLL disabled
    e)  Build the applications and Perl modules with OpenSSL disabled and winExtDLL enabled
    f)  Copy distribution files (readme, batch files etc)
    g)  Copy NSIS installer script and update the version stamp

8.  Copy the following to c:\usr\bin:

    64-bit:

    C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\redist\amd64\Microsoft.VC90.CRT\*.*

    32-bit:

    C:\Program Files\Microsoft Visual Studio 9.0\VC\redist\x86\Microsoft.VC90.CRT\*.*   

    Note:  Copy the files directly to the folder.  If you copy the folder, the binaries won't
           run on Windows 2000.

9.  Verify that the binaries created are linked to the correct MSVC 2008 redistribution that was
    copied in the previous step.

    Right-click msvcr90.dll, properties, Details.  Check the product version.  
    Example: 9.00.30729.4148

    cd \usr\bin
    mt.exe -inputresource:snmpget.exe;#1 -out:extracted.manifest
    type extracted.manifest
    
    Example:

    <assemblyIdentity type="win32" name="Microsoft.VC90.CRT" version="9.0.30729.1"
   
10. Update the BUILD INFORMATION section of c:\usr\README.txt


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

    Update these files using an HTML editor (Nvu etc):

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

1.  Complete the sections above.

2.  Launch the 'Nullsoft Install System (NSIS 2.0)'

3.  Select 'MakeNSISW (compiler interface)'

4.  Click File - Load Script

5.  Select c:\usr\net-snmp.nsi

6.  You should now have a c:\usr\Net-SNMP-x.x.x-x.exe binary installer 
    package

7.  Test the package:

    Perform the basic tests below on the following platforms:

      32-bit package:
        Windows 2000
        Windows XP 32-bit
      64-bit package:
        Windows 7 64-bit

    Tests:

    a) Installation with WinExtDLL and SSL
    b) Configure snmpd to allow a query
    c) Install snmpd and snmptrapd services
    d) Stop the Microsoft SNMP service and start both Net-SNMP services
    e) snmpwalk -v 1 -c public localhost system
    f) Install Perl modules
    g) Launch net-snmp-perl-test.pl

8.  Compare the directory contents of the compiled folder with the installed
    folder to ensure there are no missing MIB files etc.  If there are missing
    files, modify net-snmp.nsi and rebuild if required and update net-snmp.nsi
    etc in SVN.

9.  Create a .zip file of c:\usr for archive purposes.

