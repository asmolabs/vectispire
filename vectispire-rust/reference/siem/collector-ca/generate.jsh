// The certificates of reference/siem/collector-ca/, written once by BouncyCastle 1.86 — the version the control
// plane reads them with — and committed: their keys are thrown away, so a rerun writes different bytes (and the
// Java side's answers have to be regenerated after it). No private key is written anywhere.
//
//   BC=~/.gradle/caches/modules-2/files-2.1/org.bouncycastle
//   jshell --class-path "$(ls $BC/bcprov-jdk18on/1.86/*/bcprov-jdk18on-1.86.jar):$(ls $BC/bcpkix-jdk18on/1.86/*/bcpkix-jdk18on-1.86.jar):$(ls $BC/bcutil-jdk18on/1.86/*/bcutil-jdk18on-1.86.jar)" generate.jsh
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.*;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

KeyPair keys() throws Exception { var g = KeyPairGenerator.getInstance("EC"); g.initialize(256); return g.generateKeyPair(); }
String pem(String type, byte[] der) { return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der) + "\n-----END " + type + "-----\n"; }
long serial = 1000;
Date at(String instant) { return Date.from(Instant.parse(instant)); }
String cert(X500Name issuer, X500Name name, Boolean ca, Integer pathLen, Integer usage, String from, String to, boolean v1) throws Exception {
    KeyPair k = keys();
    var info = SubjectPublicKeyInfo.getInstance(k.getPublic().getEncoded());
    var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(k.getPrivate());
    serial++;
    if (v1) return pem("CERTIFICATE", new X509v1CertificateBuilder(issuer, BigInteger.valueOf(serial), at(from), at(to), name, info).build(signer).getEncoded());
    var b = new X509v3CertificateBuilder(issuer, BigInteger.valueOf(serial), at(from), at(to), name, info);
    if (ca != null) b.addExtension(Extension.basicConstraints, true, pathLen == null ? new BasicConstraints(ca) : new BasicConstraints(pathLen));
    if (usage != null) b.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
    return pem("CERTIFICATE", b.build(signer).getEncoded());
}
String cert(X500Name name, Boolean ca, Integer pathLen, Integer usage, String from, String to, boolean v1) throws Exception {
    return cert(name, name, ca, pathLen, usage, from, to, v1);
}
X500Name cn(String value) { return new X500Name(new RDN[]{ new RDN(BCStyle.CN, new DERUTF8String(value)) }); }
void write(String file, String text) throws Exception { Files.writeString(Path.of(file), text); }
String F = "2026-01-01T00:00:00Z", T = "2036-01-01T00:00:00Z";
int SIGN = KeyUsage.keyCertSign | KeyUsage.cRLSign;

write("01-root.pem", cert(cn("Corp Root"), true, null, SIGN, F, T, false));
write("02-issuing.pem", cert(cn("Corp Issuing"), true, 0, KeyUsage.keyCertSign, F, "2027-01-01T00:00:00Z", false));
write("03-leaf.pem", cert(cn("collector.corp"), false, null, KeyUsage.digitalSignature, F, T, false));
write("04-no-keycertsign.pem", cert(cn("Odd"), true, null, KeyUsage.digitalSignature, F, T, false));
write("05-expired.pem", cert(cn("Old Root"), true, null, SIGN, "2025-01-01T00:00:00Z", "2026-10-01T12:00:00Z", false));
write("06-future.pem", cert(cn("Next Root"), true, null, SIGN, "2026-10-01T12:00:01Z", T, false));
write("07-no-basic-constraints.pem", cert(cn("No Constraints"), null, null, SIGN, F, T, false));
write("08-version-1.pem", cert(cn("Version One"), null, null, null, F, T, true));
write("09-no-key-usage.pem", cert(cn("CA Without Usage"), true, null, null, F, T, false));
write("10-crlsign-only.pem", cert(cn("CRL Signer"), true, null, KeyUsage.cRLSign, F, T, false));
write("11-two-octet-usage.pem", cert(cn("Wide Usage"), true, null, KeyUsage.keyCertSign | KeyUsage.decipherOnly, F, T, false));
write("12-two-octet-no-sign.pem", cert(cn("Wide No Sign"), true, null, KeyUsage.digitalSignature | KeyUsage.decipherOnly, F, T, false));
write("13-generalized-times.pem", cert(cn("Long Lived"), true, null, SIGN, "1949-12-31T23:59:59Z", "2055-06-30T00:00:00Z", false));
write("14-utc-pivot.pem", cert(cn("Pivot"), true, null, SIGN, "1950-01-01T00:00:00Z", "2049-12-31T23:59:59Z", false));

// Names that tell two renderers apart: the escapes, a leading '#', spaces at either end, a value that is all
// spaces, an empty one, multi-valued RDNs, every string type, values that are not strings, unknown types.
X500Name name = new X500Name(new RDN[]{
    new RDN(BCStyle.C, new DERPrintableString("BE")),
    new RDN(BCStyle.O, new DERUTF8String("Exämple \"Corp\", Inc.")),
    new RDN(new AttributeTypeAndValue[]{ new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("Sec;Ops")),
        new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("a+b=c<d>e\\f")) }),
    new RDN(BCStyle.L, new DERUTF8String("  lead and trail  ")),
    new RDN(BCStyle.ST, new DERUTF8String("#hash")),
    new RDN(BCStyle.STREET, new DERUTF8String("   ")),
    new RDN(BCStyle.T, new DERUTF8String("")),
    new RDN(BCStyle.EmailAddress, new DERIA5String("a@b.example")),
    new RDN(BCStyle.DC, new DERIA5String("example")),
    new RDN(BCStyle.SERIALNUMBER, new DERPrintableString("1234")),
    new RDN(BCStyle.UID, new DERUTF8String("u1")),
    new RDN(BCStyle.CN, new DERBMPString("BMP é 😀")),
    new RDN(BCStyle.GIVENNAME, new DERT61String("télétex")),
    new RDN(BCStyle.SURNAME, new DERVisibleString("visible")),
    new RDN(BCStyle.INITIALS, new DERNumericString("123")),
    new RDN(BCStyle.PSEUDONYM, new DERUniversalString(new byte[]{0, 0, 0, 0x41})),
    new RDN(BCStyle.NAME, new ASN1Integer(42)),
    new RDN(BCStyle.DN_QUALIFIER, new DERBitString(new byte[]{(byte) 0xa0}, 5)),
    new RDN(new ASN1ObjectIdentifier("2.5.4.99"), new DERUTF8String("unknown type")),
    new RDN(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), new DERUTF8String("private arc")),
    new RDN(BCStyle.ORGANIZATION_IDENTIFIER, new DERUTF8String("VATBE-0123")),
    new RDN(BCStyle.CN, new DERUTF8String("Unicode 中 🔒 café")) });
write("15-rich-subject.pem", cert(name, true, null, SIGN, F, T, false));
write("16-hash-first.pem", cert(new X500Name(new RDN[]{ new RDN(BCStyle.CN, new DERUTF8String("#,lead")) }), true, null, SIGN, F, T, false));
write("17-empty-subject.pem", cert(cn("Some Issuer"), new X500Name(new RDN[0]), true, null, SIGN, F, T, false));

// Not a certificate: a public key (public, harmless), then a certificate wearing another label.
write("18-public-key.pem", pem("PUBLIC KEY", keys().getPublic().getEncoded()));
/exit
