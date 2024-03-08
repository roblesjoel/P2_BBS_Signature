This is the official repository of the Project 2 (course module) project about BBS Signatures.</br>
The project is part of the Bsc Computer Science course at the [BFH](https://www.bfh.ch).

Please contact [Joel Robles](mailto:joelgabriel.roblesgasser@students.bfh.ch) or [Miguel Schweizer](mailto:miguelangel.schweizer@students.bfh.ch) if there are any questions.

# Test Vectors

All test vectors of the Version 5 of the [BBS Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) are implemented and passing.

# How to play around with the implementation

### Crypto Library

The crypto Library we used is developed by Prof. Dr. Rolf Haenni.
To use the Library follow these easy steps:
1. Go into the `bbs` folder
2. Run `mvn install:install-file -Dfile=./src/main/resources/src/BLS12-381-1.0.5.jar -DpomFile=./src/main/resources/pom.xml`

### Download and install the verificatum package

This package is used by the openchvote package. </br>
Sadly it doesn't install itself, so it must be done manually. </br>
Download it from [here](https://gitlab.com/openchvote/cryptographic-protocol/-/tree/master/project-maven-repo/com/verificatum/vmgj/1.2.2?ref_type=heads).</br>
Then move all the files into `~/.m2/repository/com/verificatum/vmgj/1.2.2`<br>
You may need to create some of those folders yourself.<br>

### Run the demo

Then `cd bls` and run `mvn package` to install all the needed packages.<br>
Finally you can let it run with the command `mvn exec:java`.
This will run the code in the MainBBS.java file.

### Run your own demo

Just look at the MainBBS.java file and implement a small demo for yourself.<br>
Please report any bugs you find while running your own demo.<br>
Thanks!
