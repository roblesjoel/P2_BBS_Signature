This is the official repository of the Project 2 (course module) project about BBS Signatures.</br>
The project is part of the Bsc Computer Science course at the [BFH](https://www.bfh.ch).

Please contact [Joel Robles](mailto:joelgabriel.roblesgasser@students.bfh.ch) or [Miguel Schweizer](mailto:miguelangel.schweizer@students.bfh.ch) if there are any questions.

# Test Vectors

All test vectors mentioned in the draft are implemented.
For some tests we have not yet found out why they don't pass.
Sadly due to time constraints as the semester comes to an end, these errors will be adressed in the future.

# How to play around with the implementation

### Crypto Library

The crypto Library we used is developed by Prof. Dr. Rolf Haenni.
If you wish to play around with this implementation, please contact [Joel Robles](mailto:joelgabriel.roblesgasser@students.bfh.ch) or [Miguel Schweizer](mailto:miguelangel.schweizer@students.bfh.ch) so we can provide you the with current Crypto Library version.

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
