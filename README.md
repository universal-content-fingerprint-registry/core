# Generalized Claim Registry

## Features

### GeneralizedClaimRegistry

- **Method Registration**: Register cryptographic methods (e.g., SHA-256, MD5) with specifications
- **External ID Management**: Manage external identifiers (e.g., RSA-2048, ECDSA, HMAC) with signature size hints
- **Claim Management**: Create and manage claims with fingerprints, metadata, and external signatures
- **Batch Operations**: Support for batch claiming multiple items at once
- **Admin Controls**: Admin-only functions with optional locking mechanism

### ClaimRegistryFactory

- **Registry Creation**: Deploy new GeneralizedClaimRegistry instances with a simple function call
- **Registry Management**: Update names, descriptions, and activation status of created registries
- **Registry Discovery**: Find and track all created registries by creator or globally
- **Batch Creation**: Create multiple registries in a single transaction
- **Comprehensive Testing**: Full test suite covering all contract functionality

## Project Structure

```
├── contracts/
│   ├── GeneralizedClaimRegistry.sol    # Main smart contract
│   └── ClaimRegistryFactory.sol        # Factory contract for creating registries
├── test/
│   ├── GeneralizedClaimRegistry.test.js # Test suite for registry contract
│   └── ClaimRegistryFactory.test.js    # Test suite for factory contract
├── scripts/
│   ├── deploy.js                       # Factory deployment script
│   ├── createRegistry.js               # Script to create registries via factory
│   └── verify.js                       # Contract verification script
├── hardhat.config.js                   # Hardhat configuration
├── package.json                        # Dependencies and scripts
└── README.md                          # This file
```

## Installation

1. **Install dependencies:**

   ```bash
   npm install
   ```

2. **Install Hardhat (if not already installed):**
   ```bash
   npm install --save-dev hardhat
   ```

## Usage

### Compile Contracts

```bash
npm run compile
```

### Run Tests

```bash
npm test
```

### Deploy to Local Network

1. **Start local Hardhat node:**

   ```bash
   npm run node
   ```

2. **Deploy factory contract (in another terminal):**

   ```bash
   npm run deploy:local
   ```

3. **Create a new registry through the factory:**
   ```bash
   FACTORY_ADDRESS=0x... npm run create-registry:local
   ```

## Smart Contract Overview

### Core Structures

- **Method**: Represents a cryptographic method (e.g., SHA-256, MD5)
- **ExternalID**: Represents an external identifier (e.g., RSA-2048, ECDSA, HMAC)
- **Claim**: Represents a claim with fingerprint, metadata, and signature data

### Key Functions

#### Admin Functions

- `registerMethod()`: Register a new cryptographic method
- `registerExternalID()`: Register a new external identifier
- `setMethodActive()`: Enable/disable a method
- `setExternalIDActive()`: Enable/disable an external ID
- `lockAdmin()`: Permanently lock admin functions

#### Claim Functions

- `claimByIdwithExternalSig()`: Create a claim with external signature(eg. RSA , HMAC)
- `claimById()`: Create a claim without external signature

## Security Considerations

- Admin functions are protected and can be permanently locked
- Duplicate claims are prevented
- Signature size validation prevents oversized signatures
- Only active methods and external IDs can be used for claims

## License

MIT License - see the contract source code for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For questions or issues, please open an issue in the repository.

Framework overview: [Google Doc](https://docs.google.com/document/d/1KLkV7H3iigxn6NUcLzSgGlQngiuAQ4bHekwKbSQVGHU/edit?usp=sharing)
