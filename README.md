Module name :- strike
Creator :- Shahid Khan

	This is my little python module which helps you to create some tools on the fly (within two or three lines). Strike has ability to create 12 tools:

1.  portscanner
2.  hostscanner
3.  fuzzer
4.  ftp bruteforcer
5.  doser
6.  md5 hasher
7.  sha1 hasher
8.  sha224 hasher
9.  sha256 hasher
10. sha384 hasher
11. sha512 hasher
12. hash identifier

this module requires scapy module you can download it with pip install scapy


Here is the full documentation:

first go to the folder where strike module is and then open the terminal and open python interactive shell.....

1. if you want to create portscanner

just import the scanner class from the strike module

>>>from strike import scanner

then just type

>>>variable_name = scanner()
>>>variable_name.portscanner()

Bravo! you have just created your own portscanner :-)

<---------------------------------------------------------------->

2. if you want to create hostscanner

just import the scanner class from the strike module

>>>from strike import scanner

then just type

>>>variable_name = scanner()
>>>variable_name.hostscanner()

Bingo! your live host detector is ready to use :-)

<---------------------------------------------------------------->

3. if you want to create fuzzer

just import the fuzzer class from strike module

>>>from strike import fuzzer

then just type

>>>variable_name = fuzzer()
>>>variable_name.fuzz()

congrats! your fuzzer is ready :-)

<---------------------------------------------------------------->

4. if you want to create ftp bruteforcer

just import the bruteforcer class from the strke module

>>>from strike import bruteforcer

then just type

>>>variable_name = bruteforcer()
>>>variable_name.brutal()

now you are good to use bruteforcer :-)

<---------------------------------------------------------------->

5. if you want to create doser

just import the doser class from the strike module

>>>from strike import doser

then just type

>>>variable_name = doser()
>>>variable_name.dos()

well done!

<---------------------------------------------------------------->

6. if you want to create md5 hasher

just import the Hasher class from the strike module

>>>from strike import Hasher

then just type

>>>variable_name = Hasher()
>>>variable_name.md5()

and if you want to create other hashers then just replace the md5() with the 
algorith like sha1(), sha224(), sha256(), sha384(), sha512()
am leaving this as an exercise for you ;-)

awesome!

<---------------------------------------------------------------->

12. if you want to create hash identifier

just import the identifier class from the strike module

>>>from strike import identifier

then just type

>>>variable_name = identifier()
>>>variable_name.hashid()

easy huh!

