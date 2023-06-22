# Thesis_project
Lior Attias thesis code

## Installation steps for running the executable:
### 1. install OpenFHE

https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html

The location to where you install OpenFHE, and the location to where you install this project, should share one parent folder. In other words, they should be "sibling nodes" in the file tree.

you need to copy the 'lib' folder of OpenFHE into the parent folder of this repository

For example, after installing OpenFHE and this repository your file tree should look as follows:

```
parent_directory
- Data
- install_location_of_this_repository (this repo will automatically install the files nested in this folder for you)
- - lib (copy this lib folder from the OpenFHE project into here)
- - thesis_central_code
- - - build
- - - flex_fhe.cpp
- - - serialized_data
- - - - pattern
- - - - - zero
- - - - - one
- - - - - two
- - - - - three
- - - - text
- - - - - zero
- - - - - one
- - - - - two
- - - - - three
- install_location_of_openFHE (openFHE will automatically install the files nested in this folder for you)
- - OpenFHEDevelopment
- - - benchmark
- - - build
- - - cicd
- - - configure
- - - demodata
- - - docker
- - - docs
- - - scripts
- - - src
- - - test
- - - third-party

```


https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html

### 2. Clone this repository

```
git clone <this repository>
```

### 3. Put your data into the "data" folder

### 4. Execute the program

```
cd Thesis_project/thesis_central_code/build/

./one2
```

## Intallation steps for building the project:

### 1. install OpenFHE
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

### 2. create the directory where you want your project code to go into
```
mkdir /Users/lior/documents/research-bellovin/code2
```

#### call cmake from OpenFHE inside your project directory
```
cd /Users/lior/documents/research-bellovin/code2

cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 /Users/lior/documents/research-bellovin/code/openfhe-development

make
```

### 3. Build my project

#### Copy CMakeLists.User.txt from the root directory of the git repo to the folder for your project.

I want my code to go into 
```
/Users/lior/documents/research-bellovin/code2/liors_project/
```

Rename CMakeLists.User.txt to CMakeLists.txt.

/Users/lior/documents/research-bellovin/code2/liors_project/ should contain CMakeLists.txt

Update CMakeLists.txt to specify the name of the executable and the source code files. For example, include the following line

Now create the build folder, and execute make from from the build folder
```
cd /Users/lior/documents/research-bellovin/code2/liors_project/
mkdir build
cd build
cmake ..
make 
./test
```

each time you modify the project start file, only run 
```
make
```

