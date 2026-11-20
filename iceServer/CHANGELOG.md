# Changelog

## 0.3.1-dev

- Corrected all five Go ICE packet type identifiers to the zero-based values in Overte's `PacketTypeEnum::Value`.
- Refresh the cached Domain Server public key after a heartbeat signature failure, matching the original ICE server's key-rotation behavior.
- Added numeric golden tests and an Overte heartbeat datagram wire-layout fixture so packet type drift cannot be hidden by tests that reuse implementation constants.
- Documented the exact unreliable, unfragmented, unobfuscated UDP data-frame subset used by ICE and the source paths supporting it.
- Clarified that this implementation does not implement Overte's full reliable UDT transport; the reviewed ICE message paths use unreliable packets.

## 0.3.0-dev

- Introduced shared bootstrap enrollment secret and per-directory issued credentials.
- Removed per-directory installer prompt and manual token mapping.
- Allowed zero-domain enrollment and subsequent sync.
- Organized project as `metaStar/iceServer` alongside PHP `metaStar/directoryServer`.
- Preserved existing ICE packet implementation from 0.2.0-dev for interoperability testing.
