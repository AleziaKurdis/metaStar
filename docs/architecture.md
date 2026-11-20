# metaStar architecture

## Components

### Directory Server

The PHP Directory Server owns account, domain and directory metadata. It is designed to run on ordinary PHP hosting.

### ICE Server

The standalone Go ICE Server provides Overte's rendezvous/peer-coordination protocol and a separate authenticated control interface for Directory Services. It is intended to run on a Linux host reachable from the public Internet over UDP.

## Deployment separation

The Directory Server and ICE Server are independent processes and may run on different machines and networks. Multiple Directory Servers should be able to register with one ICE Server. Version 1 intentionally excludes directory federation.

## Compatibility requirement

The ICE implementation must interoperate with unmodified Overte Domain Servers and clients. Existing Overte packet formats and behavior are compatibility requirements, not opportunities to invent a replacement protocol. A source-level implementation is not proof of interoperability; tests with actual Overte binaries are required.

## Planned endpoint

The current design target is the same numeric port for two different transports:

- UDP 7337: Overte ICE protocol.
- TCP 7337: HTTPS control API for Directory Service enrollment and synchronization.

TCP and UDP port numbers are separate namespaces and can be bound simultaneously. Both router forwarding rules and host firewall rules must be configured independently.

The TCP API must use certificate validation on clients. Automatically generated self-signed certificates must not lead to disabling verification; the final certificate/trust model remains a deployment design item.

## Multi-directory ownership

The ICE Server maintains a mapping from each registered domain UUID to the Directory Service that owns it. Conflicting ownership claims must be rejected. Directory credentials must be unique and revocable. Enrollment must be authenticated and domain synchronization must not permit an unrelated directory to take over another directory's UUIDs.

## Non-goals for V1

- Directory federation (reserved for a later major version).
- Relaying normal world traffic.
- Changes to Overte clients or Domain Servers, unless source-level protocol analysis proves a change is unavoidable.
