#!/usr/bin/python

# Copyright 2014 Thomas Burgin.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## Thanks to Kai Engert for the inspiration
## https://bugzilla.redhat.com/show_bug.cgi?id=674684

## Thanks to Wilper, Ross; rwilper@stanford.edu
## for inspiration

## pyasn1 docs
## http://pyasn1.sourceforge.net/tagging.html

import	re,		\
		sys,	 \
		argparse
from pyasn1.codec.der import encoder
from pyasn1.type import univ, \
						char,  \
						tag

class ASN1Integer(univ.Integer):
	def tagExplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagExplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))
	def tagImplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagImplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))

class ASN1Sequence(univ.Sequence):
	def tagExplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagExplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))
	def tagImplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagImplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))
	def fillSequence(self, vals):
		for i in range(len(vals)):
			self.setComponentByPosition(i, vals[i])

class ASN1GeneralString(char.GeneralString):
	def tagExplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagExplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))
	def tagImplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagImplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))

class ASN1IA5String(char.IA5String):
	def tagExplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagExplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))
	def tagImplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagImplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))

class ASN1OctetString(univ.OctetString):
	def tagExplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagExplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))
	def tagImplicitly(self, tagged=0):
		self._tagSet = self.tagSet.tagImplicitly(
			tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tagged))

'''
----------------------------------------------------------------------
-- AlternativeNames 
-- XCN_OID_SUBJECT_ALT_NAME2 (2.5.29.17)
----------------------------------------------------------------------

AltNames ::= SEQUENCE --#public-- OF GeneralName
GeneralNames ::= AltNames

GeneralName ::= CHOICE 
{
   otherName               [0] IMPLICIT OtherName,		-- Only 1.3.6.1.5.2.2 (PK-INIT)
   rfc822Name              [1] IMPLICIT IA5STRING,
   dNSName                 [2] IMPLICIT IA5STRING,
   x400Address             [3] IMPLICIT SeqOfAny,		-- Not supported
   directoryName           [4] EXPLICIT ANY,			-- Not supported
   ediPartyName            [5] IMPLICIT SeqOfAny,		-- Not supported
   uniformResourceLocator  [6] IMPLICIT IA5STRING,
   iPAddress               [7] IMPLICIT OCTETSTRING,
   registeredID            [8] IMPLICIT EncodedObjectID	-- Not supported
}
'''

def encodeRFC822names(rfc822List):
	ret = []
	if rfc822List:
		for e in rfc822List:
			rfc822 = ASN1IA5String(e)
			rfc822.tagImplicitly(1)
			ret.append(rfc822)
	return ret

def encodeDNSNames(dnsList):
	ret = []
	if dnsList:
		for e in dnsList:
			dns = ASN1IA5String(e)
			dns.tagImplicitly(2)
			ret.append(dns)
	return ret

def encodeUniforms(uniformList):
	ret = []
	if uniformList:
		for e in uniformList:
			uniform = ASN1IA5String(e)
			uniform.tagImplicitly(6)
			ret.append(uniform)
	return ret

def encodeIPAddress(ipaddressList):
	ret = []
	if ipaddressList:
		for e in ipaddressList:
			ipaddress = ASN1OctetString(e)
			ipaddress.tagImplicitly(7)
			ret.append(ipaddress)
	return ret


'''
Realm ::=           GeneralString

PrincipalName ::=   SEQUENCE {
                    name-type[0]     INTEGER,
                    name-string[1]   SEQUENCE OF GeneralString
}

KRB5PrincipalName ::= SEQUENCE {
  realm                   [0] Realm,
  principalName           [1] PrincipalName
}
'''

def encodePKINIT(pkinitList):
	ret = []
	for e in pkinitList:
		
		principalExpanded = re.split(r'[/@]+', e)
		
		if len(principalExpanded) != 3:
			print "[!] PK-INIT Principal [%s] is not valid.\
			\n\tUse something like this krbtgt/COMPANY.COM@COMPANY.COM" % e
			continue

		realm = ASN1GeneralString(principalExpanded[2])
		realm.tagExplicitly(0)
		
		nameType = ASN1Integer(1)
		nameType.tagExplicitly(0)
		nameString = ASN1Sequence()
		nameString.tagExplicitly(1)
		nameString.fillSequence(
			[char.GeneralString(principalExpanded[0]), 
			char.GeneralString(principalExpanded[1])])

		principalName = ASN1Sequence()
		principalName.tagExplicitly(1)
		principalName.fillSequence([nameType, nameString])

		krb5PrincipalName = ASN1Sequence()
		krb5PrincipalName.tagExplicitly(0)
		krb5PrincipalName.fillSequence([realm, principalName])
		ret.append(krb5PrincipalName)
	
	return ret

'''
OtherName ::= SEQUENCE 
{
   type                    EncodedObjectID,
   value                   [0] EXPLICIT NOCOPYANY 
}
'''

def encodeOtherName(otherNameHash):
	ret = []
	otherNames = []
	otherName = ASN1Sequence()
	otherName.tagImplicitly(0)
	
	for key, value in otherNameHash.iteritems():
		for e in value:
			oid = univ.ObjectIdentifier(key)
			otherNames.extend([oid, e])
	
	otherName.fillSequence(otherNames)
	ret.append(otherName)
	return ret


def main(argv):

	parser = argparse.ArgumentParser(
		description="SubjectAltName Builder")
	parser.add_argument("-r", "--rfc822name", nargs="+")
	parser.add_argument("-d", "--dnsname", nargs="+", 
		help="--dnsname DC.COMPANY.COM COMPANY.COM COMPANY.")
	parser.add_argument("-u", "--uniformresourcelocator", nargs="+")
	parser.add_argument("-i", "--ipaddress", nargs="+")
	parser.add_argument("-p", "--pk-init", nargs="+", 
		help="--pk-init krbtgt/COMPANY.COM@COMPANY.COM\
		 krbtgt/SUB.COMPANY.COM@SUB.COMPANY.COM.")
	##parser.add_argument("-o", "--othername-extension", nargs=2)
	parser.add_argument("-w", "--write-to-file", 
		help="--write-to-file /path/to/der/output")

	args = parser.parse_args()

	sanList = []

	rfc822List = encodeRFC822names(args.rfc822name)
	if len(rfc822List) > 0:
		sanList.extend(rfc822List)

	dnsList = encodeDNSNames(args.dnsname)
	if len(dnsList) > 0:
		sanList.extend(dnsList)

	uniformList = encodeUniforms(args.uniformresourcelocator)
	if len(uniformList) > 0:
		sanList.extend(uniformList)

	ipaddressList = encodeIPAddress(args.ipaddress)
	if len(ipaddressList) > 0:
		sanList.extend(ipaddressList)

	otherNameHash = {}
	otherNameEncodedList = []
	pkinitList = encodePKINIT(args.pk_init)
	if len(pkinitList) > 0:
		otherNameHash["1.3.6.1.5.2.2"] = pkinitList

	## Add Other OtherName OID support here
	
	if len(otherNameHash) > 0:
		otherNameEncodedList = encodeOtherName(otherNameHash)

	if len(otherNameEncodedList) > 0:
		sanList.extend(otherNameEncodedList)

	if len(sanList) == 0:
		sys.exit("[!] No SAN Items to encode")

	subjectAltName = ASN1Sequence()
	subjectAltName.fillSequence(sanList)
	subjectAltNameEncoded = encoder.encode(subjectAltName)
	print "[+] Done. Here is your hex encoded DER SAN."
	print str(subjectAltNameEncoded).encode("hex") 
	
	if args.write_to_file:
		print "[+] Writing DER SAN File: [%s]" % args.write_to_file
		outfile = open(args.write_to_file, "wb");
		outfile.write(subjectAltNameEncoded)
		outfile.close()

if __name__ == "__main__":
    main(sys.argv[1:])
