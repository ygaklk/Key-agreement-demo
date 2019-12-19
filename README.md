# Key agreement demonstrator

This is a quick python3 script to experiment the Diffie-Hellman key exchange algorithm + key derivation algorithm.

First implmentation uses elliptic curves (ECDH) with the x25519 curve for the agreement and HKDF function for the derivation..

## Usage
To simulate the exchange between 2 entities, you must start the script in 2 different windows:
- Start the first entity with: `python3 ecdh_exchange.py --device`
- Start the second entity with: `python3 ecdh_exchange.py --joinserver`
- Copy the first public key and paste it inside the second screen, as it is requested
- Do the same operation in the opposite way
- Validate the keys
- Now, observe that both entities share the same secret keys, without any other exchanges

Note: the autonomous mode is not implemented yet.
