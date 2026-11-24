
A 1-shot AI written Fritzbox secret decoder.

Created after failing to get other recommended ones working - this worked straight away

do-what-you-want license
Shared in case it is helpful!

Decrypt the "$$$$..." secrets in a FRITZ!Box settings export (.export) file.

Usage:  python3 fritz_decode.py backup.export "export-password" [-a]

Prints the readable lines that contained secrets (SIP/phone/Wi-Fi etc.).
Use -a to write the whole file with every secret decrypted instead.
Needs:  pip install cryptography
Runs entirely locally; nothing is sent anywhere.

