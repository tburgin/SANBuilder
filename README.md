# SANBuilder
Build the SubjectAltName of an x509 certificate

## Run it
You will need to install `pyasn1`
```zsh
sudo easy_install pyasn1
```

SAN Builder has support for the common SAN feilds
```zsh
→ ./san_builder.py --help 
usage: san_builder.py [-h] [-r RFC822NAME [RFC822NAME ...]]
                      [-d DNSNAME [DNSNAME ...]]
                      [-u UNIFORMRESOURCELOCATOR [UNIFORMRESOURCELOCATOR ...]]
                      [-i IPADDRESS [IPADDRESS ...]]
                      [-p PK_INIT [PK_INIT ...]] [-w WRITE_TO_FILE]

SubjectAltName Builder

optional arguments:
  -h, --help            show this help message and exit
  -r RFC822NAME [RFC822NAME ...], --rfc822name RFC822NAME [RFC822NAME ...]
  -d DNSNAME [DNSNAME ...], --dnsname DNSNAME [DNSNAME ...]
                        --dnsname DC.COMPANY.COM COMPANY.COM COMPANY.
  -u UNIFORMRESOURCELOCATOR [UNIFORMRESOURCELOCATOR ...], --uniformresourcelocator UNIFORMRESOURCELOCATOR [UNIFORMRESOURCELOCATOR ...]
  -i IPADDRESS [IPADDRESS ...], --ipaddress IPADDRESS [IPADDRESS ...]
  -p PK_INIT [PK_INIT ...], --pk-init PK_INIT [PK_INIT ...]
                        --pk-init krbtgt/COMPANY.COM@COMPANY.COM
                        krbtgt/SUB.COMPANY.COM@SUB.COMPANY.COM.
  -w WRITE_TO_FILE, --write-to-file WRITE_TO_FILE
                        --write-to-file /path/to/der/output
```

## Example
```zsh
→ ./san_builder.py -d KDC.COMP.COM COMP.COM COMP \
	-p krbtgt/COMP.COM@COMP.COM \
	-w pk-init_san.der 
[+] Done. Here is your hex encoded DER SAN.
3057820c4b44432e434f4d502e434f4d8208434f4d502e434f4d8204434f4d50a03706062b0601050202a02d302ba00a1b08434f4d502e434f4da11d301ba003020101a11430121b066b72627467741b08434f4d502e434f4d
[+] Writing DER SAN File: [pk-init_san.der]
```

Here is the parsed SAN

![screen shot 2015-08-11 at 4 46 45 pm](https://cloud.githubusercontent.com/assets/2117646/9210164/a9f0f816-4048-11e5-867c-d7dd71f5536b.png)


## Why?
OS X uses a variant of Heimdal Kerberos.
To PK-INIT with Heimdal there must be a subjectAltName otherName using OID id-pkinit-san (1.3.6.1.5.2.2) in the type field and a DER encoded KRB5PrincipalName that matches the name of the TGS of the target realm.

Microsoft's Certificate Enrollment does not encode the KRB5PrincipalName within the OtherName within the SubjectAltName properly. It will always embed the DER KRB5PrincipalName within an OctectString. It needs to be inline and not buried inside an OctectString.

I have build this utility to generate the whole `SubjectAltName`, in turn encoding the `OtherName` and `KRB5PrincipalName` properly.

  *  You can then use Microsoft's Certificate Enrollment to generate your certificate, just leave the `Alternative Name` in the `Subject Tab` blank.

![blank](https://cloud.githubusercontent.com/assets/2117646/9209219/57b67a8a-4043-11e5-9846-7c1f7d2a7467.png)

  *  Then use the `custom extention definition` to overwrite the whole SAN using OID `2.5.29.17`

![san](https://cloud.githubusercontent.com/assets/2117646/9209220/5a2cce5e-4043-11e5-8642-adc0a79ad176.png)

## Sources

  *  http://www.h5l.org/manual/HEAD/info/heimdal/Setting-up-PK_002dINIT.html
  *  https://bugzilla.redhat.com/show_bug.cgi?id=674684
  *  Wilper, Ross; rwilper@stanford.edu
  *  http://pyasn1.sourceforge.net/tagging.html

## License

Copyright 2015 Thomas Burgin.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
