use 5.00006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'NetSNMP::TrapReceiver',
    'VERSION_FROM'	=> 'TrapReceiver.pm', # finds $VERSION
    'PREREQ_PM'		=> { NetSNMP::OID => 5.1 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'TrapReceiver.pm', # retrieve abstract from module
       AUTHOR     => 'W. Hardaker <hardaker@users.sourceforge.net>') : ()),
    'LIBS'		=> [''], # e.g., '-lm'
    'DEFINE'		=> '', # e.g., '-DHAVE_SOMETHING'
    'INC'		=> '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # 'OBJECT'		=> '$(O_FILES)', # link all the C files too
);
if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
  my @names = (qw(NETSNMPTRAPD_AUTH_HANDLER NETSNMPTRAPD_HANDLER_BREAK
		 NETSNMPTRAPD_HANDLER_FAIL NETSNMPTRAPD_HANDLER_FINISH
		 NETSNMPTRAPD_HANDLER_OK NETSNMPTRAPD_POST_HANDLER
		 NETSNMPTRAPD_PRE_HANDLER));
  ExtUtils::Constant::WriteConstants(
                                     NAME         => 'NetSNMP::TrapReceiver',
                                     NAMES        => \@names,
                                     DEFAULT_TYPE => 'IV',
                                     C_FILE       => 'const-c.inc',
                                     XS_FILE      => 'const-xs.inc',
                                  );

}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}
