# HsmKeyWrappingExample

This code provides simple examples to play with key wrapping on the
SafeNet Luna SA HSM provided by Amazon's AWS CloudHSM offering.

## Why this is interesting?
If you're only managing, say 20k keys, you can store them on the Luna SA HSM.
Each key is physically stored on the HSM and accessed via a string label that
you set.

Managing larger numbers of keys is typically done by storing encrypted versions
of those keys outside the HSM.  A Key Encrption Key (KEK) is stored on the HSM
to generate the encrypted host key.

## Severe issue with the AWS CloudHSM
Ideally, the KEK can unwrap the encrypted host key on the HSM and allow
the unwrapped key to be used in crypto operations, but never allow the HSM
client to query back the unwrapped host key in the clear.  In my testing
with the Luna SA 8000 provided by Amazon CloudHSM, there is no way to do this.
The HSM was always willing to give back the unwrapped key in the clear when
calling *getEncoded()* on the key.

**Update:  The behavior I'm seeing is due to a defect in the Luna SA 5.1 
firmware.  This version has a bug where any key unwrapped on the HSM is
extractable.  (An impressive defect considering the cost and purpose of this
device!)  Safenet claims release 5.2 and above fixes the issue, but the AWS
CloudHSM version at the time of this writing is 5.1.2-2 so I am unable to
confirm.**

**Update 2: Amazon says they can update CloudHSM instances to firmware
5.3.1.  I'll update this REAMDE again in a few months after I get sign-off on
upgrading and try the updated firmware.**
http://docs.aws.amazon.com/cloudhsm/latest/upgrade/cloud-hsm-upgrade-guide.html


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

4) To run one of the alternate examples, swap the main class declared in
the build.gradle file or the main class on the command line if invoking java
directly.
