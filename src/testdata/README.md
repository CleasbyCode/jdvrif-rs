Twitter carrier regression fixtures
==================================

`twitter_low_amplitude.jpg` is a generated 400×400 progressive YCbCr 4:2:0
JPEG with Q90 quantization and every luminance AC coefficient set to +1. Its
advertised payload capacity is 7,851 bytes. Embedding near that capacity turns
some coefficients into zero and exercises recovery's invariant position bound.

`twitter_oversized_header.jpg` and `twitter_maximum_header.jpg` use the same
cover with valid keyed carrier headers (key 42) declaring 7,852 and 4,294,967,295
payload bytes respectively. Their valid checksums ensure that the decoder
reaches the payload capacity check.

These are synthetic test images containing no personal or external content.
Regenerate them using the commands at the top of
`generate_twitter_capacity_fixtures.cpp`; no additional downloads are needed.
