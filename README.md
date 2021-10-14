# Alberta Vaccine QR Code Security Audit

## Motivation
I was bored, and I wanted to see if our mostly incompetent government did the right thing and made the Vaccine QR codes secure.

## Findings
- While the QR code format has a few deterrents to obtain the underlying metadata (First Name, Last Name, Date of Birth, Vaccines), it is not impossible as proved by this audit. It is however using encryption to ensure that it cannot be tempered with.
- The metadata is formatted based on the [SMART Health Card framework](https://smarthealth.cards/ial)
- The application itself simply decodes the QR code, decrypts the metadata and verifies that the contents have been signed using one of the authorized issuers private encryption key which makes secure.

## Reverse Engineering Outline
In order to reverse engineer the encoding format of the QR code I needed to get two things:
- A valid QR code issued by the government
- A copy of the AB Covid Records Verifier Android APK [com.ab.gov.covidrecordsverifier](https://play.google.com/store/apps/details?id=ca.ab.gov.covidrecordsverifier)

## Tools Used
- Eclipse for Java Development
- VS Code for Javascript Development
- QR Code Decoder - https://zxing.org/w/decode.jspx
- JWT Playground - https://jwt.io
- JADX Dex to Java Decompiler - https://github.com/skylot/jadx

## Now the fun begins
I used an online QR Code decoder where you can upload an image, and it will give you the raw text payload which is in the following format:
```
shc:/123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890...
```

Doing a simple string lookup in the APK's source for the `shc:/` prefix yielded the following find. It's a helper function that takes every digit pair that follows the `shc:/` prefix and converts them into a character from the ASCII character map:

Here is the Java implementation:
```java
private final String d(String str) {
    List list = y.s0(str, new String[]{"shc:/"}, false, 0, 6, null);
    if (list.size() < 2) {
        return null;
    }
    StringBuffer stringBuffer = new StringBuffer();
    Matcher matcher = Pattern.compile("[0-9]{2}").matcher((String) list.get(1));
    while (matcher.find()) {
        String group = matcher.group();
        k.d(group, "m.group()");
        int parseInt = Integer.parseInt(group, kotlin.r0.b.a(10)) + 45;
        if (parseInt < kotlin.a.a(0) || parseInt > kotlin.a.a(65535)) {
            throw new IllegalArgumentException("Invalid Char code: " + parseInt);
        }
        stringBuffer.append((char) (b0.m((short) parseInt) & 65535));
    }
    return stringBuffer.toString();
}
```

To make things a bit simpler I made a Javascript function that does exactly what the function above does:
```js
var shcDigitPairs = `12
34
56
78
90`; 
var buffer = "";
shcDigitPairs.split("\n").forEach(s => {
  // I'm not sure if this is just a proprietary deterrent but it parses
  // the digit pair then adds the arbitrary number 45 to it. 
  const int = parseInt(s, 10) + 45;
  buffer += String.fromCharCode(int);
});

console.log(buffer);
```

Once I obtained the decoded string from the original payload, I immediately noticed it was a [JSON Web Signature](https://jwt.io/) so I headed over to the online console and tried decoding the token to see if I could extract the metadata I was after:
<img alt="screenshot" src="https://puu.sh/Iid00/58ac4bb68c.png" />

## A quick overview of JSON Web Signatures:
They are typically in a 3 part format:
`<base64encode(headerJsonString)>`
`.`
`<base64encode(payloadJsonString)>`
`.`
`<base64encode(signatureJsonString)>`

See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) for more details about JWS

In this case the second part (payload) would return gibberish which usually means that it's either been encoded/encrypted or in this particular case. Back to the source code:

After digging some more in the APK and following a bunch of obfuscated classes and methods we arrive here:
```java
private final VaccineCard c(String str) {
    try {
        j k2 = j.k(str);
        k.d(k2, "JWSObject.parse(jwsString)");
        byte[] a = d.a(k2.b().d());
        k.d(a, "DeflateUtils.decompress(zippedPayload.toBytes())");
        Object i2 = d.c.a.d.d.a.f5330b.a().i(new String(a, kotlin.r0.d.a), new C0146a().getType());
        k.d(i2, "gson.fromJson(json, type)");
        if (!(i2 instanceof VaccineCard)) {
            i2 = null;
        }
        return (VaccineCard) i2;
    } catch (Exception e2) {
        d.c.a.c.b.e(this, "Error while parsing DVC JWS structure", e2);
        return null;
    }
}
```

This function essentially takes the second part of the JWS payload and converts it to an array of bytes which can then be unzipped to reveal the actual payload. For this case I had to rebuild the function in Java and use native libraries to achieve my goal:
```java
package covidverifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.util.zip.Inflater;
import java.util.zip.DataFormatException;

import com.nimbusds.jwt.*;

public class Main
{
    public static void main(String[] args)
    {
        // The token has been redacted for privacy purposes
    	String jwtString = "fake.jwt.token";
    	
    	try {
            SignedJWT jwt = SignedJWT.parse(jwtStr);
            byte[] payloadBytes = jwt.getPayload().toBytes();		
            byte[] inflatedBytes = inflate(payloadBytes);
            System.out.println(new String(inflatedBytes, "UTF-8"));	
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (DataFormatException e) {
            e.printStackTrace();
        }
    }
    
    public static byte[] inflate(byte[] data) throws IOException, DataFormatException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(data);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[65536];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();
        return output;
    }
}
```

### Here's the sauce
So after about 12 hours of reverse engineering, we get the final payload (some values were redacted for privacy purposes):
```json
{
  "iss": "https://covidrecords.alberta.ca/smarthealth/issuer",
  "nbf": 1111111111,
  "vc": {
    "type": [
      "https://smarthealth.cards#health-card",
      "https://smarthealth.cards#covid19",
      "https://smarthealth.cards#immunization"
    ],
    "credentialSubject": {
      "fhirVersion": "4.0.1",
      "fhirBundle": {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
          {
            "fullUrl": "resource:0",
            "resource": {
              "resourceType": "Patient",
              "name": [
                {
                  "family": "redacted",
                  "given": [
                    "redacted"
                  ]
                }
              ],
              "birthDate": "0000-00-00"
            }
          },
          {
            "fullUrl": "resource:1",
            "resource": {
              "resourceType": "Immunization",
              "meta": {
                "security": [
                  {
                    "system": "https://smarthealth.cards/ial",
                    "code": "IAL1.2"
                  }
                ]
              },
              "status": "completed",
              "vaccineCode": {
                "coding": [
                  {
                    "system": "http://hl7.org/fhir/sid/cvx",
                    "code": "207"
                  }
                ]
              },
              "patient": {
                "reference": "Patient/resource:0"
              },
              "occurrenceDateTime": "0000-00-00",
              "performer": [
                {
                  "actor": {
                    "display": "Government of Alberta - Provincial Immunization Repository"
                  }
                }
              ],
              "lotNumber": "UNK"
            }
          }
        ]
      }
    }
  }
}
```