# SpainMobileID

Decoder for **Spain Mobile ID** (DNI / MiDNI) QR codes, based on the [ICAO 9303-13](https://www.icao.int/publications/Documents/9303_p13_cons_en.pdf) Visible Digital Seal (VDS) standard.

The Spanish _Policía Nacional_ MiDNI app generates QR codes containing identity data signed with ECDSA. This tool parses those QR payloads and extracts all embedded fields.

## Features

- Parses ICAO 9303-13 VDS headers (C40 encoding, BER-TLV)
- Extracts identity fields: name, surnames, DOB, sex, document number, expiry, nationality, address, birthplace, parents, support number
- Handles age, simple, and complete verification types
- Extracts embedded JPEG2000 thumbnail photo
- Extracts ECDSA signature and signed data for verification
- Auto-strips QR byte-mode headers from raw codeword input
- Extensible base class (`VDSDecoder`) for other ICAO 9303-13 profiles

## Usage

### From a binary QR payload

```sh
python SpainMobileIDDecoder.py --file payload.bin
```

### From stdin (binary)

```sh
cat payload.bin | python SpainMobileIDDecoder.py --stdin
```

### From a hex string

```sh
python SpainMobileIDDecoder.py 'dc037581759ea9b5...'
```

### From stdin (hex)

```sh
echo 'dc037581759ea9b5...' | python SpainMobileIDDecoder.py --stdin --input-format hex
```

### Decoding a QR from an image

Use any QR code reader that outputs raw binary data. For example, with [zbarimg](https://github.com/mchehab/zbar):

```sh
zbarimg --raw --oneshot -Sbinary Examples/SpainMobileID-QR-Example-1.png | python SpainMobileIDDecoder.py --stdin
```

### Extracting the thumbnail photo

```sh
# Save to file
python SpainMobileIDDecoder.py --file payload.bin --save-image photo.jp2

# Open directly
python SpainMobileIDDecoder.py --file payload.bin --open-image
```

### JSON output

```sh
python SpainMobileIDDecoder.py --file payload.bin --json
```

## Example Output

```
=================================================================
  Spain Mobile ID — Decoded Seal
=================================================================

  Header
  ---------------------------------------------
  Version:                      3
  Issuing country:              ES
  Signer ID:                    ESPN
  Certificate reference:        2274948240B9368F65E5C80FEBFE5CE4
  Document issue date:          17-06-2025
  Signature creation date:      17-06-2025
  Verification type:            Complete
  Document type:                Spain Mobile ID (DNI / MiDNI)

  Fields
  ---------------------------------------------
  Document number:              00000446D
  First name:                   JOSE
  Surnames:                     ESPAÑOL ESPAÑOL
  Date of birth:                01-10-1978
  Sex:                          M
  Document expiry date:         13-09-2028
  Nationality:                  ESP
  Parents' names:               DANIEL / PILAR
  Physical DNI support #:       CAA000481
  Full address:                 C. SOL 1
  Address (1):                  MADRID
  Address (2):                  MADRID
  Birthplace (1):               MADRID
  Birthplace (2):               MADRID
  QR data expiry:               17-06-2030 10:44:16
  Thumbnail image:              [871 bytes JPEG2000]
  ECDSA signature:              E03B755E81F15C94...

=================================================================
```

## QR Payload Format

The QR payload follows [ICAO Doc 9303 Part 13](https://www.icao.int/publications/Documents/9303_p13_cons_en.pdf) (Visible Digital Seals):

| Section   | Contents                                                        |
|-----------|-----------------------------------------------------------------|
| Header    | Magic (0xDC), version, country (C40), signer/cert ref (C40), dates, feature ref, doc type |
| Message   | TLV-encoded fields (tag + BER length + value)                   |
| Signature | TLV with tag 0xFF containing raw ECDSA r‖s                     |

The signing certificate can be obtained from https://pki.policia.es/cnp/MiDNI using the certificate reference from the header.

## Requirements

Python 3.10+ (no external dependencies).

## License

MIT
