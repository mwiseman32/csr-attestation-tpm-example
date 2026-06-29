from pyasn1.type import univ, namedtype
from pyasn1.codec.der.encoder import encode

#
# OIDs
#

id_tcg_attest_certify = (2, 23, 133, 20, 1)
id_tcg_attest_quote   = (2, 23, 133, 20, 2)

#
# ASN.1 definitions
#

class AttestationStatement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'type',
            univ.ObjectIdentifier()
        ),
        namedtype.NamedType(
            'stmt',
            univ.OctetString()
        )
    )


class AttestationStatements(univ.SequenceOf):
    componentType = AttestationStatement()


#
# Placeholder for your certificate type.
# Replace with the CMS LimitedCertChoices definition.
#

class LimitedCertChoices(univ.Any):
    pass


class CertificateSet(univ.SequenceOf):
    componentType = LimitedCertChoices()


class AttestationBundle(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'attestations',
            AttestationStatements()
        ),
        namedtype.OptionalNamedType(
            'certs',
            CertificateSet()
        )
    )


#
# Build example bundle
#

bundle = AttestationBundle()

#
# First attestation (TPM2_Certify)
#

certify = AttestationStatement()
certify['type'] = univ.ObjectIdentifier(id_tcg_attest_certify)
certify['stmt'] = b'\x01\x02\x03\x04'

#
# Second attestation (TPM2_Quote)
#

quote = AttestationStatement()
quote['type'] = univ.ObjectIdentifier(id_tcg_attest_quote)
quote['stmt'] = b'\x11\x22\x33\x44\x55'

atts = AttestationStatements()
atts.append(certify)
atts.append(quote)

bundle['attestations'] = atts

#
# Encode as DER
#

der = encode(bundle)

print("DER length:", len(der))
print("DER hex:")
print(der.hex())

