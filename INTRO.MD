# Introduction to the GeneralizedClaimRegistry Contract

## What is the GeneralizedClaimRegistry?

The `GeneralizedClaimRegistry` is a Solidity smart contract that provides a flexible system for recording and verifying claims about digital content. It allows users to create immutable records of ownership, authenticity, or other properties of digital assets using cryptographic fingerprints and optional external signatures.

## Core Concepts

### Claims

A **claim** is a record that associates a digital fingerprint (hash) of some content with metadata, ownership information, and optional cryptographic signatures. Claims are immutable once created and provide verifiable proof of when and by whom they were made.

### Fingerprints

**Fingerprints** are cryptographic hashes (like SHA-256) of digital content. They serve as unique identifiers that can verify the integrity and authenticity of the original content without revealing the content itself.

### Methods

**Methods** define the cryptographic algorithms used to generate fingerprints (e.g., SHA-256, MD5, SHA-512). Each method has a unique ID and specifies the expected fingerprint size.

### External IDs

**External IDs** represent additional verification mechanisms like digital signatures (RSA, ECDSA) or message authentication codes (HMAC). They provide an extra layer of authenticity beyond the basic fingerprint.

## Contract Architecture

The `GeneralizedClaimRegistry` contract provides:

### Core Data Structures

- **Method**: Defines cryptographic hash functions (SHA-256, MD5, etc.)
- **ExternalID**: Defines external signature schemes (RSA, ECDSA, HMAC, etc.)
- **Claim**: Records containing fingerprints, metadata, and optional signatures

### Key Features

- Register cryptographic methods and external signature types
- Create claims with fingerprints, metadata, and optional signatures
- Batch claim operations for efficiency
- Admin controls with optional permanent locking
- View functions for retrieving claims and metadata

## Use Cases

### Document Timestamping

Create immutable timestamps for any document by recording its cryptographic hash:

```solidity
// SHA-256 hash of document content
claim({ methodId: 1, externalId: 1, fingerprint: documentHash, externalSig: "0x", pubKey: "0x", metadata: "Research Paper v1.0", extURI: "https://university.edu/paper123" });
```

### Signed Content Verification

Combine content hashes with external signatures for stronger authenticity:

```solidity
// Content hash with RSA signature
claim({ methodId: 1, externalId: 1, fingerprint: contentHash, externalSig: rsaSignature, pubKey: publicKey, metadata: "Signed Report", extURI: "" });
```

### Batch Content Registration

Efficiently register multiple pieces of content in a single transaction:

```solidity
// Register multiple documents at once
batchClaimById(methodId, externalId, hashArray, metadataArray, uriArray);
```

### Integrity Verification

Verify that content hasn't been tampered with by checking stored fingerprints:

```solidity
// Retrieve and verify existing claim
Claim memory claim = getClaimById(methodId, contentHash);
require(claim.owner != address(0), "No claim found");
```

## Key Benefits

### Immutability

- Claims cannot be altered once created
- Permanent record on the blockchain
- Cryptographic proof of timestamp and ownership

### Flexibility

- Support for multiple cryptographic hash methods
- Optional external signature verification
- Customizable metadata for each claim
- Batch operations for gas efficiency

### Decentralization

- No single point of failure
- Censorship-resistant records
- Global accessibility

### Transparency

- All claims are publicly verifiable
- Open-source smart contract
- Auditable on-chain history

## Technical Features

### Contract Structure

```solidity
contract GeneralizedClaimRegistry {
    // Core data structures
    struct Method { uint16 methodId; string name; string specURI; uint32 fpSizeBytes; bool active; }
    struct ExternalID { uint16 extId; string specURI; uint32 sigSizeHint; bool active; }
    struct Claim { address owner; string metadata; bytes fingerprint; /* ... */ }

    // Storage mappings
    mapping(uint16 => Method) public methods;
    mapping(uint16 => ExternalID) public externalIDs;
    mapping(uint16 => mapping(bytes32 => Claim)) public claimsById;
}
```

### Gas Efficiency

- Optimized storage layout using `uint16` for IDs
- Batch operations to reduce transaction costs
- Minimal on-chain storage (content stored off-chain)
- Efficient keccak256-based claim lookup

### Security Features

- Admin controls with optional permanent locking via `lockAdmin()`
- Signature size validation to prevent oversized data
- Duplicate claim prevention through unique digest keys
- Method/ExternalID activation controls

### Access Patterns

- **Admin-only**: Method/ExternalID registration and management
- **Public**: Claim creation and retrieval
- **View functions**: Gas-free claim lookups

## Contract Functions

### Admin Functions (Admin-only, unless locked)

- `registerMethod(uint16 methodId, string name, string specURI, uint32 fpSizeBytes)`
- `registerExternalID(uint16 extId, string specURI, uint32 sigSizeHint)`
- `setMethodActive(uint16 methodId, bool active)`
- `setExternalIDActive(uint16 extId, bool active)`
- `transferAdmin(address newAdmin)`
- `lockAdmin()` - Permanently locks admin functions

### Claim Functions (Public)

- `claim(ClaimParams)` - Create a claim with optional external signature and public key
  // Batch helpers can be implemented off-chain by iterating claim()

### View Functions (Public, gas-free)

- `getClaimById(uint16 methodId, bytes fingerprint)` - Returns full claim
- `getClaimByIdWithExtId(uint16 methodId, bytes fingerprint, uint16 extId)` - With external ID
- `getMetadataById(uint16 methodId, bytes fingerprint, uint16 sigId)` - Metadata only

## Getting Started

### 1. Deploy Contract

Deploy `GeneralizedClaimRegistry.sol` to your preferred network.

### 2. Register Methods

As admin, register cryptographic methods you'll use:

```solidity
registerMethod(1, "SHA-256", "https://tools.ietf.org/html/rfc6234", 32);
```

### 3. Create Claims

Users can now create claims:

```solidity
claim({ methodId: 1, externalId: 1, fingerprint: contentHash, externalSig: "0x", pubKey: "0x", metadata: "My Document", extURI: "https://example.com/doc" });
```

### 4. Retrieve Claims

Anyone can verify claims:

```solidity
Claim memory claim = getClaimById(1, contentHash);
```

## Next Steps

1. **Read the detailed usage guide**: See [HOW_TO_USE.MD](HOW_TO_USE.MD) for complete API documentation
2. **Explore the contract**: Review `contracts/GeneralizedClaimRegistry.sol`
3. **Deploy and test**: Start with a local deployment to understand the contract behavior

The `GeneralizedClaimRegistry` provides a powerful foundation for building content verification systems, timestamping services, and authenticity tracking applications on the blockchain.
