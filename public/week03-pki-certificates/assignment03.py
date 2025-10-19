import argparse
import sys
import os
import ssl
import socket
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, dsa
from cryptography.exceptions import InvalidSignature


def load_cert_from_file(path):
    data = open(path, "rb").read()
    return load_cert_from_bytes(data)

def load_cert_from_bytes(data):
    """
    Accepts DER or PEM bytes and returns an x509.Certificate
    """
    try:
        # Try DER first
        cert = x509.load_der_x509_certificate(data, default_backend())
        return cert
    except Exception:
        try:
            cert = x509.load_pem_x509_certificate(data, default_backend())
            return cert
        except Exception as e:
            raise ValueError("Failed to parse certificate (not PEM or DER)") from e

def download_certificate(hostname, port=443, timeout=10):
    
   # Download cert from a website, gives DER bytes.
    
    context = ssl.create_default_context()
    #  want the raw cert even if it wouldn't validate 
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
            return der

def fmt_datetime(dt):
    if isinstance(dt, datetime.datetime):
        return dt.isoformat()
    return str(dt)

#parsing
def parse_certificate(cert):
    
    #cert: x509.Certificate object
    #returns dict of parsed info
    
    info = {}
    info['subject'] = cert.subject.rfc4514_string()
    info['issuer'] = cert.issuer.rfc4514_string()
    info['serial_number'] = hex(cert.serial_number)
    info['not_before'] = fmt_datetime(cert.not_valid_before)
    info['not_after'] = fmt_datetime(cert.not_valid_after)
    # signature algorithm
    try:
        info['signature_algorithm'] = cert.signature_algorithm_oid._name
    except Exception:
        info['signature_algorithm'] = cert.signature_algorithm_oid.dotted_string
    info['version'] = cert.version.name

    # key info
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        info['public_key_type'] = 'RSA'
        info['public_key_size'] = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        info['public_key_type'] = 'ECDSA'
        try:
            info['public_key_curve'] = pub.curve.name
        except Exception:
            info['public_key_curve'] = str(pub.curve)
    elif isinstance(pub, dsa.DSAPublicKey):
        info['public_key_type'] = 'DSA'
    else:
        info['public_key_type'] = type(pub).__name__

    # Extensions
    exts = {}
    for ext in cert.extensions:
        oid = ext.oid
        try:
            if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                san = ext.value
                exts['subject_alt_names'] = [str(name) for name in san]
            elif oid == ExtensionOID.BASIC_CONSTRAINTS:
                bc = ext.value
                exts['basic_constraints'] = {
                    "ca": bc.ca,
                    "path_length": bc.path_length
                }
            elif oid == ExtensionOID.KEY_USAGE:
                ku = ext.value
                exts['key_usage'] = {k: bool(getattr(ku, k)) for k in [
                    'digital_signature', 'content_commitment', 'key_encipherment',
                    'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign',
                    'encipher_only', 'decipher_only'
                ]}
            elif oid == ExtensionOID.EXTENDED_KEY_USAGE:
                eku = ext.value
                exts['extended_key_usage'] = [oid.dotted_string for oid in eku]
            else:
                # Stores a repr for extensions
                exts[str(oid)] = str(ext.value)
        except Exception:
            exts[str(oid)] = "Unable to parse extension"

    info['extensions'] = exts

    return info

def pretty_print_info(info):
    print("Subject:    ", info.get('subject'))
    print("Issuer:     ", info.get('issuer'))
    print("Serial:     ", info.get('serial_number'))
    print("Version:    ", info.get('version'))
    print("Valid From: ", info.get('not_before'))
    print("Valid To:   ", info.get('not_after'))
    print("Signature Alg:", info.get('signature_algorithm'))
    print("Public Key: ", info.get('public_key_type'), info.get('public_key_size', ''))
    print("\nExtensions:")
    for k, v in info.get('extensions', {}).items():
        print("  ", k, ":", v)

#validation
def verify_signature(child_cert: x509.Certificate, issuer_cert: x509.Certificate):
    
    #Verify that issuer_cert signed child_cert.
    #Returns (True, None) or (False, "reason")
    
    issuer_pub = issuer_cert.public_key()
    signature = child_cert.signature
    tbs = child_cert.tbs_certificate_bytes
    hash_algo = child_cert.signature_hash_algorithm
    if hash_algo is None:
        return False, "Unknown signature hash algorithm"

    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            issuer_pub.verify(
                signature,
                tbs,
                padding.PKCS1v15(),
                hash_algo
            )
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(signature, tbs, ec.ECDSA(hash_algo))
        elif isinstance(issuer_pub, dsa.DSAPublicKey):
            issuer_pub.verify(signature, tbs, hash_algo)
        else:
            return False, f"Unsupported issuer public key type: {type(issuer_pub)}"
    except InvalidSignature:
        return False, "Invalid signature (verification failed)"
    except Exception as e:
        return False, f"Signature verification error: {e}"

    return True, None

def check_dates(cert: x509.Certificate, now=None):
    now = now or datetime.datetime.utcnow()
    if cert.not_valid_before > now:
        return False, f"Certificate not valid yet (not_before={cert.not_valid_before.isoformat()})"
    if cert.not_valid_after < now:
        return False, f"Certificate expired (not_after={cert.not_valid_after.isoformat()})"
    return True, None

def is_self_signed(cert: x509.Certificate):
    # subject == issuer, signature verifies with public key
    if cert.subject.rfc4514_string() != cert.issuer.rfc4514_string():
        return False
    try:
        pub = cert.public_key()
        signature = cert.signature
        tbs = cert.tbs_certificate_bytes
        hash_algo = cert.signature_hash_algorithm
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, tbs, padding.PKCS1v15(), hash_algo)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, tbs, ec.ECDSA(hash_algo))
        else:
            # try generic verify
            pub.verify(signature, tbs, hash_algo)
        return True
    except Exception:
        return False

def build_chain_from_files(leaf_path, chain_paths=None, root_path=None):
    
    #Build list: [leaf_cert, intermediate..., root_cert?]
    #chain_paths: list of file paths for intermediates (optional)
    #root_path: file path for root (optional)
    
    chain = []
    leaf = load_cert_from_file(leaf_path)
    chain.append(leaf)
    if chain_paths:
        for p in chain_paths:
            chain.append(load_cert_from_file(p))
    if root_path:
        chain.append(load_cert_from_file(root_path))
    return chain

def validate_chain(chain_certs, trusted_roots=None):
    
    #chain_certs: list of x509.Certificate from leaf to (possible) root
    #trusted_roots: list of x509.Certificate considered trusted roots
    #Returns dict with  boolean, errors, warnings, and detailed per-link results
    
    results = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "links": []  # list of per-link 
    }

    now = datetime.datetime.utcnow()

    # Check dates for cert
    for idx, cert in enumerate(chain_certs):
        ok, reason = check_dates(cert, now)
        if not ok:
            results['valid'] = False
            results['errors'].append(f"Certificate at position {idx} date check failed: {reason}")
        # warn on short key sizes
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
            results['warnings'].append(f"Certificate at position {idx} uses RSA key size {pub.key_size} (<2048)")

    # Verify link signatures
    for i in range(len(chain_certs)-1):
        child = chain_certs[i]
        issuer = chain_certs[i+1]
        ok, reason = verify_signature(child, issuer)
        link = {
            "child_subject": child.subject.rfc4514_string(),
            "issuer_subject": issuer.subject.rfc4514_string(),
            "signature_valid": ok,
            "reason": reason
        }
        results['links'].append(link)
        if not ok:
            results['valid'] = False
            results['errors'].append(f"Signature verification failed for {child.subject.rfc4514_string()}: {reason}")

    # Check final root
    if len(chain_certs) >= 1:
        final = chain_certs[-1]
        if is_self_signed(final):
            # If trusted_roots provided, see if final matches an entry
            if trusted_roots:
                found = False
                for r in trusted_roots:
                    if r.subject == final.subject and r.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo
                    ) == final.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo
                    ):
                        found = True
                        break
                if not found:
                    results['warnings'].append("Root certificate is self-signed but not in provided trusted roots (untrusted).")
                    results['valid'] = False
            else:
                results['warnings'].append("Chain ends in a self-signed certificate (root). No trusted_roots provided to confirm trust anchor.")
        else:
            results['errors'].append("Chain does not end in a self-signed root certificate.")
            results['valid'] = False

    return results

# commands

def cmd_analyze(args):
    path = args.file
    if args.host:
        # download
        print(f"Downloading certificate from {args.host}...")
        der = download_certificate(args.host, port=args.port)
        cert = load_cert_from_bytes(der)
    else:
        cert = load_cert_from_file(path)
    info = parse_certificate(cert)
    pretty_print_info(info)

def cmd_download(args):
    host = args.host
    der = download_certificate(host, port=args.port)
    # Save as PEM
    cert = x509.load_der_x509_certificate(der, default_backend())
    pem = cert.public_bytes(serialization.Encoding.PEM)
    out = args.out if args.out else f"{host}.pem"
    with open(out, "wb") as f:
        f.write(pem)
    print(f"Saved certificate from {host} -> {out}")

def cmd_validate(args):
    # Load certs
    leaf = load_cert_from_file(args.cert)
    chain_paths = args.chain or []
    root_path = args.root
    chain_certs = [leaf]
    for p in chain_paths:
        chain_certs.append(load_cert_from_file(p))
    if root_path:
        chain_certs.append(load_cert_from_file(root_path))
    trusted_roots = None
    if args.trusted_roots:
        trusted_roots = [load_cert_from_file(p) for p in args.trusted_roots]

    results = validate_chain(chain_certs, trusted_roots=trusted_roots)
    print("Validation Results:")
    print("  Valid:", results['valid'])
    if results['errors']:
        print("  Errors:")
        for e in results['errors']:
            print("   -", e)
    if results['warnings']:
        print("  Warnings:")
        for w in results['warnings']:
            print("   -", w)
    print("\nLink details:")
    for link in results['links']:
        print(f"  Child: {link['child_subject']}")
        print(f"   Issuer: {link['issuer_subject']}")
        print(f"   Signature valid: {link['signature_valid']}")
        if link['reason']:
            print(f"   Reason: {link['reason']}")
        print("")

def cert_to_summary(cert):
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": fmt_datetime(cert.not_valid_before),
        "not_after": fmt_datetime(cert.not_valid_after),
        "serial": hex(cert.serial_number)
    }

def cmd_compare(args):
    c1 = load_cert_from_file(args.cert1)
    c2 = load_cert_from_file(args.cert2)
    s1 = cert_to_summary(c1)
    s2 = cert_to_summary(c2)
    print("Certificate 1 Summary:")
    for k,v in s1.items():
        print(f"  {k}: {v}")
    print("\nCertificate 2 Summary:")
    for k,v in s2.items():
        print(f"  {k}: {v}")

    print("\nDifferences:")
    diffs = []
    for key in ['subject', 'issuer', 'serial', 'not_before', 'not_after']:
        if s1.get(key) != s2.get(key):
            diffs.append((key, s1.get(key), s2.get(key)))
    if diffs:
        for d in diffs:
            print(f"  {d[0]}:\n    cert1: {d[1]}\n    cert2: {d[2]}")
    else:
        print("  No differences in core fields.")

# cli

def main():
    parser = argparse.ArgumentParser(description="Certificate Analyzer & Validator")
    sub = parser.add_subparsers(dest="cmd")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze a certificate file or host")
    p_analyze.add_argument("--file", help="Certificate file path (PEM/DER). Required if --host not provided")
    p_analyze.add_argument("--host", help="Download cert from host (overrides --file)")
    p_analyze.add_argument("--port", type=int, default=443)
    p_analyze.set_defaults(func=cmd_analyze)

    # download
    p_download = sub.add_parser("download", help="Download certificate from host and save as PEM")
    p_download.add_argument("--host", required=True)
    p_download.add_argument("--port", type=int, default=443)
    p_download.add_argument("--out", help="Output PEM file")
    p_download.set_defaults(func=cmd_download)

    # validate
    p_validate = sub.add_parser("validate", help="Validate certificate chain")
    p_validate.add_argument("--cert", required=True, help="Leaf/server certificate (PEM/DER)")
    p_validate.add_argument("--chain", nargs='*', help="Intermediate certificates (PEM/DER) in order from leaf->...->issuer")
    p_validate.add_argument("--root", help="Root certificate (PEM/DER)")
    p_validate.add_argument("--trusted-roots", nargs='*', help="Paths to trusted root cert(s) to compare with chain root")
    p_validate.set_defaults(func=cmd_validate)

    # compare
    p_compare = sub.add_parser("compare", help="Compare two certificates")
    p_compare.add_argument("--cert1", required=True)
    p_compare.add_argument("--cert2", required=True)
    p_compare.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
