# Thesis_project
Lior Attias thesis code

## Installation steps for running the re-creating timeing and performance metrics:
### 1. install OpenFHE

https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html

The location to where you install OpenFHE, and the location to where you install this project, should share one parent folder. In other words, they should be "sibling nodes" in the file tree.

you need to copy the 'lib' folder of OpenFHE into the parent folder of this repository

For example, after installing OpenFHE and this repository your file tree should look as follows:

```
parent_directory
- Data
- install_location_of_this_repository (this repo will install the files nested in this folder for you)
- - lib (copy this lib folder from the OpenFHE project into here)
- - thesis_central_code
- - - build
- - - flexFHE.cpp
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
- install_location_of_openFHE (openFHE will install the files nested in this folder for you)
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

./flexFHE
```

## Intallation steps for building the project:

### 1. install OpenFHE
```
brew install cmake

brew install libomp
```

#### install location of OpenFHE
```
mkdir /Users/username/documents/research/code/openfhe-development

cd /Users/username/documents/research/code/openfhe-development
```

#### clone the OpenFHE repository
```
git clone https://github.com/openfheorg/openfhe-development.git
```

### 2. create the directory where you want your project code to go into
```
mkdir /Users/username/documents/research/flexFHESource
```

#### call cmake from OpenFHE inside your project directory
```
cd /Users/username/documents/research/flexFHESource

cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 /Users/username/documents/research/code/openfhe-development

make
```

### 3. Build my project

#### Copy CMakeLists.User.txt from the root directory of the git repo to the folder for your project.

I want my code to go into 
```
/Users/username/documents/research/flexFHESource
```

/Users/username/documents/research/flexFHESource/ should contain CMakeLists.txt

Update CMakeLists.txt to specify the name of the executable and the source code files. For example, include the following line

Now create the build folder, and execute make from from the build folder
```
cd /Users/username/documents/research/flexFHESource/
mkdir build
cd build
cmake ..
make 
./flexFHE
```

each time you modify the project start file, only run 
```
make
```

# Steps for executing the software as Alice and Bob
•	Install OpenFHE
•	Clone the Thesis_project repository
•	Create a new build folder and build the project
  ```
  cd build
  rm -f CMakeCache.txt
  cmake ..
  make
  ```
•	In Alice’s secure environment, encrypt the genome
```
./trust
```
•	In Bob’s untrusted environment, run calculations on the encrypted genome
```
./untrust
```
•	In Alice’s trusted environment, verify the calcuations are correct by running:
```
./trust_decr
```
•	In Bob’s untrusted environment, create a public/private key pair for Bob.
```
./bob_key
```
•	In Alice’s secure environment, run the re-encryption protocol to re-encrypt the data
```
./trust_reenc
```
•	In Bob’s untrusted environment, decrypt the results with Bob’s private key
```
./untrust_decr
```

Where To Place Genome, Pattern, and Homolog Files:

•	In trust.cpp, define the absolute paths to your local files.
  set the variable ```infilename ``` to the absolute path of your genome.
  set the variable ```pattern ```to your pattern
    The pattern  is a sequence of nucleotides such as aattt
set the variable ```homo (short for homolog)``` to a wildcard pattern 
  A wildcard pattern contains the character X such as aaXXXttt
set the ```variable percent_file_name``` to the absolute path of another genome (or any sequence of nucleotides) to perform a perform a percent match operation on.
  The results of a percent match operation will tell you the percent of matching nucleotides between the original genome sequence and another genome sequence. The longer the continuous matching sequence and the higher the percent match between the two sequences, the greater likelihood of familial relationship between the two genomes.

  
![image](https://github.com/lattias/Thesis_project/assets/16942812/c03e9a54-aed9-47db-a304-29853cf92603)

