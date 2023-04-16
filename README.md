Simple MBUS/COSEM decryptor/decoder for smartmeter
==================================================

This contains a simple MBUS/COSEM decryptor/decoder. Supports smartmeters that send their data via MBUS and encrypted via GLO.
Output can either be CSV or postgres/timescaledb database.

Requires:

- recent python 3
- cryptography
- optionally psycopg2 for postgres/timescaledb support
- optionally pyserial for reading data directly from serial port

Tested with Kaifa MA309M.
