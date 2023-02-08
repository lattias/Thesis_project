# Thesis_project
Lior Attias thesis code

Intallation steps

## 1. install OpenFHE
```
brew install cmake

brew install libomp
```

#### install location of OpenFHE
```
mkdir /Users/lior/documents/research-bellovin/code/openfhe-development

cd /Users/lior/documents/research-bellovin/code/openfhe-development
```

#### clone the OpenFHE repository
```
git clone https://github.com/openfheorg/openfhe-development.git
```

## 2. create the directory where you want your project code to go into
```
mkdir /Users/lior/documents/research-bellovin/code2
```

#### call cmake from OpenFHE inside your project directory
```
cd /Users/lior/documents/research-bellovin/code2

cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 /Users/lior/documents/research-bellovin/code/openfhe-development

make
```

#### Copy CMakeLists.User.txt from the root directory of the git repo to the folder for your project.

Rename CMakeLists.User.txt to CMakeLists.txt.

Update CMakeLists.txt to specify the name of the executable and the source code files. For example, include the following line

## 3. Build my project
```
mkdir build
cd build
cmake ..
```
