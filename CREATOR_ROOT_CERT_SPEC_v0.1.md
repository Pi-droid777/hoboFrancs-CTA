# Creator Root Certificate Specification (CRCS)
Version: 0.1 (Draft)

## Purpose
Define a creator-native certificate model that can evolve
into a delegated root trust authority for attribution.

## Certificate Layers
1. Creator Leaf Certificate (Current)
2. Platform-Verified Intermediate (Future)
3. Creator Root Certificate Authority (Target)

## Required Fields
- Creator ID (UUID or DID)
- Creation Timestamp (UTC)
- Work Hash (SHA-256)
- Device Binding Hash
- Certificate Signature

## Trust Model
- Self-issued certificates in Beta
- Verifier-based trust scoring
- Future root delegation by platforms

## Non-Goals
- Not impersonating public CAs
- Not replacing copyright offices
- Not acting as a system root today

## End State
A globally recognized trust layer where
creation itself produces a verifiable certificate.
