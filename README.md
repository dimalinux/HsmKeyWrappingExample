# HsmKeyWrappingExample

This code provides a simple example to play with key wrapping on the
SafeNet Luna SA HSM provided by Amazon's AWS CloudHSM offering.

## Why this is interesting to me
If you're only managing, say 20k keys, you can store them on the HSM.  If you
need to manage more by saving encrypted host keys, the Luna SA is problematic.

With the Luna EFT HSM you can do crypto operations directly with encrypted
host keys.  The HSM does not even provide a transformation to convert an
encrypted host key back to its unencrytped form.  The transactions are like
this:
```
[Client => HSM]  encryptedHostKey, operation type, inputData
[Client <= HSM]  transformed result
```

The Luna SA is problematic.  You can create your own KEK (key encryption key)
on the HSM, but in order to use an encrypted host key created by it, you must
first decrypt the host key exposing the original unencrypted key value to the
client. A Safenet representative pointed out that **after decrypting the key**
we can inject the key into the HSM for the length of the session.  In an
application that runs for hours or days, this would provide meaningful protection
against memory attacks (reading memory of the applicaiton for keys), but in our
use case the keys are used immedaitely and then the JVM exits.

## How to use this code

1) Create a test partition on your HSM and record the partition name and password.

2) Create a partition.properties file in your home directory with the following
two properties: 
```
partitionName = YourTestPartitionName
partitionPass = PasswordForYourTestPartition
```

3) From a Linux HSM client host with the Luna SA JSP client software installed:
```
$ git clone https://github.com/dimalinux/HsmKeyWrappingExample.git
$ cd HsmKeyWrappingExample

$ ./gradlew clean run
# Or:
$ ./gradlew clean build
$ java -Djava.library.path=/usr/lunasa/jsp/lib -cp build/libs/HsmKeyWrappingExample.jar:/usr/lunasa/jsp/lib/LunaProvider.jar to.noc.hsm.lunasa.example.KeyWrappingExample
```
