

from .python_rsakey import Python_RSAKey
from .python_ecdsakey import Python_ECDSAKey
from .python_dsakey import Python_DSAKey
from .pem import dePem, pemSniff
from .asn1parser import ASN1Parser
from .cryptomath import bytesToNumber, powMod
from .compat import compatHMAC
from ecdsa.curves import NIST256p, NIST384p, NIST521p
from ecdsa.keys import SigningKey, VerifyingKey

class Python_Key(object):
    """
    Generic methods for parsing private keys from files.

    Handles both RSA and ECDSA keys, irrespective of file format.
    """

    @staticmethod
    def parsePEM(s, passwordCallback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""

        if pemSniff(s, "PRIVATE KEY"):
            bytes = dePem(s, "PRIVATE KEY")
            return Python_Key._parse_pkcs8(bytes)
        elif pemSniff(s, "RSA PRIVATE KEY"):
            bytes = dePem(s, "RSA PRIVATE KEY")
            return Python_Key._parse_ssleay(bytes, "rsa")
        elif pemSniff(s, "DSA PRIVATE KEY"):
            bytes = dePem(s, "DSA PRIVATE KEY")
            return Python_Key._parse_dsa_ssleay(bytes)
        elif pemSniff(s, "EC PRIVATE KEY"):
            bytes = dePem(s, "EC PRIVATE KEY")
            return Python_Key._parse_ecc_ssleay(bytes)
        else:
            raise SyntaxError("Not a PEM private key file")

    @staticmethod
    def _parse_pkcs8(bytes):
        parser = ASN1Parser(bytes)

        # first element in PrivateKeyInfo is an INTEGER
        version = parser.getChild(0).value
        if bytesToNumber(version) != 0:
            raise SyntaxError("Unrecognized PKCS8 version")

        # second element in PrivateKeyInfo is a SEQUENCE of type
        # AlgorithmIdentifier
        alg_ident = parser.getChild(1)
        seq_len = alg_ident.getChildCount()
        # first item of AlgorithmIdentifier is an OBJECT (OID)
        oid = alg_ident.getChild(0)
        if list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
            key_type = "rsa"
        elif list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
            key_type = "rsa-pss"
        elif list(oid.value) == [42, 134, 72, 206, 56, 4, 1]:
            key_type = "dsa"
        elif list(oid.value) == [42, 134, 72, 206, 61, 2, 1]:
            key_type = "ecdsa"
        else:
            raise SyntaxError("Unrecognized AlgorithmIdentifier: {0}"
                              .format(list(oid.value)))
        # second item of AlgorithmIdentifier are parameters (defined by
        # above algorithm)
        if key_type == "rsa":
            if seq_len != 2:
                raise SyntaxError("Missing parameters for RSA algorithm ID")
            parameters = alg_ident.getChild(1)
            if parameters.value != bytearray(0):
                raise SyntaxError("RSA parameters are not NULL")
        if key_type == "dsa":
            if seq_len != 2:
                raise SyntaxError("Invalid encoding of algorithm identifier")
            parameters = alg_ident.getChild(1)
            if parameters.value == bytearray(0):
                parameters = None
        elif key_type == "ecdsa":
            if seq_len != 2:
                raise SyntaxError("Invalid encoding of algorithm identifier")
            curveID = alg_ident.getChild(1)
            if list(curveID.value) == [42, 134, 72, 206, 61, 3, 1, 7]:
                curve = NIST256p
            elif list(curveID.value) == [43, 129, 4, 0, 34]:
                curve = NIST384p
            elif list(curveID.value) == [43, 129, 4, 0, 35]:
                curve = NIST521p
            else:
                raise SyntaxError("Unknown curve")
        else:  # rsa-pss
            pass  # ignore parameters - don't apply restrictions

        if seq_len > 2:
            raise SyntaxError("Invalid encoding of AlgorithmIdentifier")

        #Get the privateKey
        private_key_parser = parser.getChild(2)

        #Adjust for OCTET STRING encapsulation
        private_key_parser = ASN1Parser(private_key_parser.value)

        if key_type == "ecdsa":
            return Python_Key._parse_ecdsa_private_key(private_key_parser,
                                                       curve)
        elif key_type == "dsa":
            return Python_Key._parse_dsa_private_key(private_key_parser, parameters)
        else:
            return Python_Key._parse_asn1_private_key(private_key_parser,
                                                      key_type)

    @staticmethod
    def _parse_ssleay(data, key_type="rsa"):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For RSA keys.
        """
        private_key_parser = ASN1Parser(data)
        # "rsa" type as old format doesn't support rsa-pss parameters
        return Python_Key._parse_asn1_private_key(private_key_parser, key_type)

    @staticmethod
    def _parse_dsa_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For DSA keys.
        """
        private_key_parser = ASN1Parser(data)
        return Python_Key._parse_dsa_private_key(private_key_parser)

    @staticmethod
    def _parse_ecc_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.

        For ECDSA keys.
        """
        private_key_parser = ASN1Parser(data)

        # Parse version
        version = private_key_parser.getChild(0)
        if version.value != b'\x01':
            raise SyntaxError("Unexpected EC private key version")

        # Parse private key
        private_key_bytes = private_key_parser.getChild(1).value

        # Parse curve parameters (if present)
        curve = None
        if private_key_parser.getChildCount() > 2:
            curve_params = private_key_parser.getChild(2)
            # Check if it's a direct OID or wrapped in context-specific tag
            if curve_params.value[0] == 0x06:  # OBJECT IDENTIFIER
                curve_oid = curve_params.value[2:]  # Skip tag and length
            elif curve_params.value[0] == 0xa0:  # context-specific tag [0]
                curve_oid_parser = ASN1Parser(curve_params.value[2:])
                curve_oid = curve_oid_parser.value
            else:
                raise SyntaxError("Unknown curve parameter format")

            if list(curve_oid) == [42, 134, 72, 206, 61, 3, 1, 7]:
                curve = NIST256p
            elif list(curve_oid) == [43, 129, 4, 0, 34]:
                curve = NIST384p
            elif list(curve_oid) == [43, 129, 4, 0, 35]:
                curve = NIST521p
            else:
                raise SyntaxError("Unknown curve")

        if curve is None:
            raise SyntaxError("Cannot determine curve from EC private key")

        # Parse public key if present
        public_key = None
        if private_key_parser.getChildCount() > 3:
            public_key_data = private_key_parser.getChild(3)
            # This should be a BIT STRING directly
            if public_key_data.value[0] == 0x03:  # BIT STRING
                # Skip tag, length, and unused bits byte
                if public_key_data.value[2] == 0:  # No unused bits
                    public_key_bytes = public_key_data.value[3:]
                    # Parse as uncompressed point
                    if public_key_bytes[0] == 0x04:  # Uncompressed format
                        coord_len = (len(public_key_bytes) - 1) // 2
                        x_bytes = public_key_bytes[1:1+coord_len]
                        y_bytes = public_key_bytes[1+coord_len:]
                        x = bytesToNumber(x_bytes)
                        y = bytesToNumber(y_bytes)
                        public_key = (x, y)

        # Create SigningKey from private key bytes
        private_key = SigningKey.from_string(compatHMAC(private_key_bytes), curve)
        secret_mult = private_key.privkey.secret_multiplier

        if public_key:
            return Python_ECDSAKey(public_key[0], public_key[1], curve.name, secret_mult)
        else:
            # Calculate public key from private key
            verifying_key = private_key.get_verifying_key()
            pub_x = verifying_key.pubkey.point.x()
            pub_y = verifying_key.pubkey.point.y()
            return Python_ECDSAKey(pub_x, pub_y, curve.name, secret_mult)

    @staticmethod
    def _parse_ecdsa_private_key(private, curve):
        ver = private.getChild(0)
        if ver.value != b'\x01':
            raise SyntaxError("Unexpected EC key version")
        private_key = private.getChild(1)
        public_key = private.getChild(2)
        # first two bytes are the ASN.1 custom type and the length of payload
        # while the latter two bytes are just specification of the public
        # key encoding (uncompressed)
        # TODO: update ecdsa lib to be able to parse PKCS#8 files
        if curve is not NIST521p:
            if list(public_key.value[:1]) != [3] or \
                    list(public_key.value[2:4]) != [0, 4]:
                raise SyntaxError("Invalid or unsupported encoding of public key")

            pub_key = VerifyingKey.from_string(
                    compatHMAC(public_key.value[4:]),
                    curve)
        else:
            if list(public_key.value[:3]) != [3, 129, 134] or \
                    list(public_key.value[3:5]) != [0, 4]:
                raise SyntaxError("Invalid or unsupported encoding of public key")

            pub_key = VerifyingKey.from_string(
                    compatHMAC(public_key.value[5:]),
                    curve)
        pub_x = pub_key.pubkey.point.x()
        pub_y = pub_key.pubkey.point.y()
        priv_key = SigningKey.from_string(compatHMAC(private_key.value),
                                          curve)
        mult = priv_key.privkey.secret_multiplier
        return Python_ECDSAKey(pub_x, pub_y, curve.name, mult)

    @staticmethod
    def _parse_asn1_private_key(private_key_parser, key_type):
        version = private_key_parser.getChild(0).value[0]
        if version != 0:
            raise SyntaxError("Unrecognized RSAPrivateKey version")
        n = bytesToNumber(private_key_parser.getChild(1).value)
        e = bytesToNumber(private_key_parser.getChild(2).value)
        d = bytesToNumber(private_key_parser.getChild(3).value)
        p = bytesToNumber(private_key_parser.getChild(4).value)
        q = bytesToNumber(private_key_parser.getChild(5).value)
        dP = bytesToNumber(private_key_parser.getChild(6).value)
        dQ = bytesToNumber(private_key_parser.getChild(7).value)
        qInv = bytesToNumber(private_key_parser.getChild(8).value)
        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv, key_type)


    @staticmethod
    def _parse_dsa_private_key(private_key_parser, domain_parameters=None):
        if domain_parameters:
            p = bytesToNumber(domain_parameters.getChild(0).value)
            q = bytesToNumber(domain_parameters.getChild(1).value)
            g = bytesToNumber(domain_parameters.getChild(2).value)
            x = bytesToNumber(private_key_parser.value)
            y = powMod(g, x, p)  # Calculate public key from private key
            return Python_DSAKey(p, q, g, x, y)
        p = bytesToNumber(private_key_parser.getChild(1).value)
        q = bytesToNumber(private_key_parser.getChild(2).value)
        g = bytesToNumber(private_key_parser.getChild(3).value)
        y = bytesToNumber(private_key_parser.getChild(4).value)
        x = bytesToNumber(private_key_parser.getChild(5).value)
        return Python_DSAKey(p, q, g, x, y)
