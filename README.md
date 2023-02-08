# Thesis_project
Lior Attias thesis code

Intallation steps

## 1. install OpenFHE
brew install cmake
brew install libomp

### install location of OpenFHE
mkdir /Users/lior/documents/research-bellovin/code/openfhe-development
cd /Users/lior/documents/research-bellovin/code/openfhe-development

### clone the OpenFHE repository
https://github.com/openfheorg/openfhe-development.git

## 2. create the directory where you want your project code to go into
mkdir /Users/lior/documents/research-bellovin/code2

### call cmake from OpenFHE inside your project directory
cd /Users/lior/documents/research-bellovin/code2
cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 /Users/lior/documents/research-bellovin/code/openfhe-development
make
