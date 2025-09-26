# How to Use the GeneralizedClaimRegistry Contract

This guide explains how to interact with the GeneralizedClaimRegistry.sol smart contract.

## Contract Overview

The `GeneralizedClaimRegistry` contract allows you to:

- Register cryptographic methods (SHA-256, MD5, etc.)
- Register external signature types (RSA, ECDSA, HMAC, etc.)
- Create claims with fingerprints and optional external signatures
- Retrieve and verify existing claims

## Contract Deployment

Deploy the contract using your preferred method:

```javascript
// Using ethers.js
const GeneralizedClaimRegistry = await ethers.getContractFactory(
  "GeneralizedClaimRegistry"
);
const registry = await GeneralizedClaimRegistry.deploy();
await registry.waitForDeployment();
console.log("Registry deployed to:", await registry.getAddress());
```

## Working with the Contract

### Setting Up Methods and External IDs (Admin Only)

```javascript
// Connect to the deployed contract
const registry = await ethers.getContractAt(
  "GeneralizedClaimRegistry",
  registryAddress
);

// Register cryptographic methods
await registry.registerMethod(
  1, // Method ID
  "SHA-256", // Method name
  "https://tools.ietf.org/html/rfc6234", // Specification URI
  32 // Fingerprint size in bytes
);

await registry.registerMethod(
  2,
  "MD5",
  "https://tools.ietf.org/html/rfc1321",
  16
);

// Register external signature methods
await registry.registerExternalID(
  1, // External ID
  "https://tools.ietf.org/html/rfc8017", // Specification URI
  256 // Signature size hint (0 = variable)
);

await registry.registerExternalID(2, "https://tools.ietf.org/html/rfc6979", 64);
```

### Making Claims

#### Simple Claim (without external signature)

```javascript
const fingerprint = "0x1234567890abcdef..."; // Your content fingerprint
const methodId = 1; // SHA-256
const externalId = 1; // Example external ID
const metadata = "My document claim";
const extURI = "https://mydomain.com/document";
await registry.claim({
  methodId,
  externalId,
  fingerprint,
  externalSig: "0x",
  pubKey: "0x",
  metadata,
  extURI,
});
```

#### Claim with External Signature

```javascript
const fingerprint = "0x1234567890abcdef...";
const methodId = 1; // SHA-256
const externalId = 1; // RSA-2048
const externalSig = "0x..."; // RSA signature
const pubKey = "0x..."; // RSA public key
const metadata = "Signed document claim";
const extURI = "https://mydomain.com/document";
await registry.claim({
  methodId,
  externalId,
  fingerprint,
  externalSig,
  pubKey,
  metadata,
  extURI,
});
```

#### Batch Claims

```javascript
// For multiple claims at once
const fingerprints = ["0x123...", "0x456...", "0x789..."];
const metadatas = ["Doc 1", "Doc 2", "Doc 3"];
const extURIs = [
  "https://example.com/1",
  "https://example.com/2",
  "https://example.com/3",
];
// Use multiple individual claim() calls or implement a batch helper off-chain
for (let i = 0; i < fingerprints.length; i++) {
  await registry.claim({
    methodId,
    externalId,
    fingerprint: fingerprints[i],
    externalSig: "0x",
    pubKey: "0x",
    metadata: metadatas[i],
    extURI: extURIs[i],
  });
}
```

### Retrieving Claims

```javascript
// Get a specific claim with external ID
const claim = await registry.getClaimByIdWithExtId(
  methodId,
  fingerprint,
  externalId
);
console.log("Claim owner:", claim.owner);
console.log("Timestamp:", claim.timestamp);
console.log("Metadata:", claim.metadata);

// Legacy helper removed: always include external ID explicitly

// Get only metadata
const metadata = await registry.getMetadataById(
  methodId,
  fingerprint,
  externalId
);
```

## Common Usage Patterns

### Document Verification

```javascript
// Set up SHA-256 method
await registry.registerMethod(
  1,
  "SHA-256",
  "https://tools.ietf.org/html/rfc6234",
  32
);

// Create a claim for a document
const documentHash = ethers.keccak256(ethers.toUtf8Bytes(documentContent));
await registry.claim({
  methodId: 1,
  externalId: 1,
  fingerprint: documentHash,
  externalSig: "0x",
  pubKey: "0x",
  metadata: "Important Document",
  extURI: "https://example.com/doc",
});
```

### Signed Content Claims

```javascript
// Set up methods and external signatures
await registry.registerMethod(1, "SHA-256", "", 32);
await registry.registerExternalID(1, "RSA-2048", "", 256);

// Create a claim with RSA signature
await registry.claim({
  methodId: 1,
  externalId: 1,
  fingerprint: contentHash,
  externalSig: rsaSignature,
  pubKey: publicKey,
  metadata: "Signed Content",
  extURI: "https://example.com",
});
```

## Admin Management

### Transferring Admin Rights

```javascript
// Transfer admin to another address (only current admin)
await registry.transferAdmin(newAdminAddress);

// Lock admin functions permanently (irreversible!)
await registry.lockAdmin();
```

### Managing Method/External ID Status

```javascript
// Temporarily disable a method
await registry.setMethodActive(methodId, false);

// Re-enable it
await registry.setMethodActive(methodId, true);

// Same for external IDs
await registry.setExternalIDActive(externalId, false);
```

## Best Practices

### Fingerprint Generation

Ensure consistent fingerprint generation:

```javascript
// For text content
const fingerprint = ethers.keccak256(ethers.toUtf8Bytes(content));

// For binary data
const fingerprint = ethers.keccak256(binaryData);
```

### Gas Optimization

Use batch operations for multiple claims to save gas costs.

## Troubleshooting

### Common Issues

**"method inactive" error**: The method ID hasn't been registered or has been deactivated.

```javascript
// Check method status
const method = await registry.methods(methodId);
console.log("Active:", method.active);
```

**"claim exists" error**: A claim with the same fingerprint and method already exists.

```javascript
// Check if claim exists
const existingClaim = await registry.getClaimByIdWithExtId(
  methodId,
  fingerprint,
  1
);
console.log("Existing owner:", existingClaim.owner);
```

**"auth" error**: You're not the admin or admin functions are locked.

```javascript
// Check admin status
const admin = await registry.admin();
const adminLocked = await registry.adminLocked();
console.log("Admin:", admin, "Locked:", adminLocked);
```

### Gas Estimation

```javascript
// Estimate gas before submitting
const gasEstimate = await registry.claim.estimateGas({
  methodId,
  externalId,
  fingerprint,
  externalSig: "0x",
  pubKey: "0x",
  metadata,
  extURI,
});
console.log("Estimated gas:", gasEstimate.toString());
```
