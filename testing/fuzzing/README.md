# Fuzzing
This folder contains a fuzzing setup that is meant to be used with OSS-Fuzz. 

Fuzzing as a concept aims to stress-test the code under analysis. Traditional
fuzzing is based on sending random input to the target application, whereas
modern fuzzing relies on genetic algorithms based on code-coverage. The goal
of the fuzzing in net-snmp is to catch any potential bugs, in particular memory
corruption issues. The net-snmp code is instrumented with different sanitizers
e.g. AddressSanitizer, when being fuzzed. 

## Building fuzz tests
The fuzz tests can be built as follows:
- Build Net-SNMP
- Run the testing/fuzzing/build.sh script

The generated executables are stored in the testing/fuzzing directory. These
executables can be run directly. However, running the fuzz tests directly does
not enable any of the OSS-Fuzz infrastructure like automatically generating a
bug report. Additionally, if not run inside a container, a fuzz test may modify
or overwrite data it should not modify.

## Running fuzz tests
The OSS-Fuzz set up can be tested in the following way:

```
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python3 ./infra/helper.py build_fuzzers net-snmp
python3 ./infra/helper.py run_fuzzer net-snmp FUZZ_NAME
```
where `FUZZ_NAME` is one of the filenames in this folder excluding the `.c`
suffix.

## OSS-Fuzz set up
In order to run fuzzers with OSS-Fuzz we need to build the fuzzers by way of
their set up. This is accomplished by the files in [this](https://github.com/google/oss-fuzz/tree/master/projects/net-snmp)
directory. In particular,
- [Dockerfile](https://github.com/google/oss-fuzz/blob/master/projects/net-snmp/Dockerfile)
clones net-snmp and sets up necessary system packages
- [build.sh](https://github.com/google/oss-fuzz/blob/master/projects/net-snmp/build.sh)
builds net-snmp and the fuzzers.

Some important notes if you want to change the build.sh file:
- The `CC`, `CXX`, `CFLAGS`, `CXXFLAGS` environment variables must be used for
compilation to ensure sanitizers are enabled.
- The `LIB_FUZZING_ENGINE` must be used for linking fuzzers
- The fuzzers must be statically linked
- The fuzzers should be moved to the `$OUT` folder.

In order to get access to the bug reports found by the fuzzers, your email
should be placed in the [project.yaml](https://github.com/google/oss-fuzz/blob/master/projects/net-snmp/project.yaml)
file. You can put it on the `auto_ccs` list, but only net-snmp maintainers
will be allowed to do so. The email must be linked to a Google account. 

When your email is in the `project.yaml` file listed above, then you can
access project details, e.g. bugs and coverage information on 
https://oss-fuzz.com
