# Sidcoin

Proof of work cryptocurrency implementing my own version of Bitcoin protocol for simplicity. Uses OpenSSL for SHA256 and ECDSA implementation.


## Progress

#### Completed

- Protocol written
- Block, transaction validation
- ECDSA and SHA256 implementation wrappers
- Serializing objects into buffers for hashing and mining according to protocol
- Single threaded mining

#### In progress

- Blockchain fork and traversal algorithms
- Optimal transaction generation

## References

https://michaelnielsen.org/ddi/how-the-bitcoin-protocol-actually-works/
https://www.youtube.com/watch?v=bBC-nXj3Ng4&vl=en
https://learnmeabitcoin.com/technical/keys/public-key/#:~:text=An%20uncompressed%20public%20key%20is,is%20an%20uncompressed%20private%20key.
https://www.openssl.org/