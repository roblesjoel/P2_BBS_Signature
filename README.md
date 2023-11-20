This is the official repository of the P2 project about BBS+ Signatures.</br>
The project is part of the Bsc Computer Science course at the [BFH](https://www.bfh.ch).

Please contact [Joel Robles](mailto:joelgabriel.roblesgasser@students.bfh.ch) or [Miguel Schweizer](mailto:miguelangel.schweizer@students.bfh.ch) if there are any questions.

# How to build and run the Demo

This demo does not run on M MacBooks!<br>
It was only tested on Debian 12.

### Download and install the verificatum package
This package is used by the openchvote package. </br>
Sadly it doesn't install itself, so it must be done manually. </br>
Download it from [here](https://gitlab.com/openchvote/cryptographic-protocol/-/tree/master/project-maven-repo/com/verificatum/vmgj/1.2.2?ref_type=heads).</br>
Then move all the files into `~/.m2/repository/com/verificatum/vmgj/1.2.2`<br>
You may need to create some of those folders yourself.<br>

### Run the demo
Then `cd bls` and run `mvn package` to install all the needed packages.<br>
Finally you can let it run with the command `mvn exec:java`.