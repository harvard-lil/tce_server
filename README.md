Time Capsule Encryption Network
===

This is an implementation of the time-lapse cryptography technique described in a [2006 paper by Michael Rabin and Christopher Thorpe](http://www.eecs.harvard.edu/~cat/tlc.pdf).
 
The system allows a distributed group of keyholders serving as trustees to generate and publish OpenPGP keys according to a fixed schedule.
Private keys are stored on airgapped computers until they are ready for publication.

By encrypting messages with the appropriate public keys, users can send messages "into the future" so they cannot be read until the
corresponding private key is released.

Design
------

The design of the system is described in our [protocol specification document](docs/design.md).

Authors
-------

This software is written by Jack Cushman. The software is developed with support from the Knight Foundation.

Copyright
---------

This software is owned by Harvard University, and released for research purposes under an
[Academic, Non-Commercial Research Use and Personal Use Software License](LICENSE.txt).