# HsmKeyWrappingExample

The HSM that Amazon provides in its CloudHSM offering is the Safenet Luna SA.
If you're only managing, say 20k keys, you can store them on the HSM.  If you
need to manage more by saving encrypted host keys, the Luna SA is problematic.

With the Luna EFT HSM you can do crypto operations directly with encrypted
host keys.  The HSM does not even provide a transformation to convert an
encrypted host key back to it's unencrytped form.  The transactions are like
this:

  Client sends: (encryptedHostKey, operation, inputData)
  HSM returns:  transformed result
  
The Luna SA is problematic.  You can create your own KEK (key encryption key)
on the HSM, but in order to use an encrypted host key created by it, you must
first decrypt the key.  This example looks at the options available.


## How to use this code

1. Create a test partition on your HSM and record the partion name and password.

2. Create a partition.properties file in your home directory with the following
two properties:
```
partitionName = YourPartitionName
partitionPass = PasswordForYourTestPartition
```
3. From a Linux HSM client host with the Luna SA JSP client software installed:
```
$ git clone https://github.com/dimalinux/HsmKeyWrappingExample.git
$ cd HsmKeyWrappingExample
$ ./gradlew clean run
# Or:
$ ../gradlew install
$ [fill this in]
```
