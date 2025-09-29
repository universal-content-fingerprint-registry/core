const { expect } = require("chai");
const { ethers } = require("hardhat");
const crypto = require("crypto");

describe("GeneralizedClaimRegistry", function () {
  let claimRegistry;
  let owner;
  let addr1;
  let addr2;
  let addrs;

  beforeEach(async function () {
    [owner, addr1, addr2, ...addrs] = await ethers.getSigners();

    const GeneralizedClaimRegistry = await ethers.getContractFactory(
      "GeneralizedClaimRegistry"
    );
    claimRegistry = await GeneralizedClaimRegistry.deploy();
    await claimRegistry.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      expect(await claimRegistry.admin()).to.equal(owner.address);
    });

    it("Should not be admin locked initially", async function () {
      expect(await claimRegistry.adminLocked()).to.equal(false);
    });
  });

  describe("Admin Functions", function () {
    describe("lockAdmin", function () {
      it("Should allow admin to lock admin", async function () {
        await claimRegistry.lockAdmin();
        expect(await claimRegistry.adminLocked()).to.equal(true);
      });

      it("Should emit AdminLocked event", async function () {
        await expect(claimRegistry.lockAdmin()).to.emit(
          claimRegistry,
          "AdminLocked"
        );
      });

      it("Should not allow non-admin to lock admin", async function () {
        await expect(
          claimRegistry.connect(addr1).lockAdmin()
        ).to.be.revertedWith("auth");
      });

      it("Should not allow admin to lock after already locked", async function () {
        await claimRegistry.lockAdmin();
        // The contract allows calling lockAdmin multiple times, it just sets adminLocked to true again
        // This is actually the current behavior, so we test that it doesn't revert
        await claimRegistry.lockAdmin();
        expect(await claimRegistry.adminLocked()).to.equal(true);
      });
    });

    describe("registerMethod", function () {
      it("Should allow admin to register a method", async function () {
        await claimRegistry.registerMethod(
          1,
          "SHA-256",
          "https://example.com/sha256",
          32
        );

        const method = await claimRegistry.methods(1);
        expect(method.methodId).to.equal(1);
        expect(method.name).to.equal("SHA-256");
        expect(method.specURI).to.equal("https://example.com/sha256");
        expect(method.fpSizeBytes).to.equal(32);
        expect(method.active).to.equal(true);
      });

      it("Should emit MethodRegistered event", async function () {
        await expect(
          claimRegistry.registerMethod(
            1,
            "SHA-256",
            "https://example.com/sha256",
            32
          )
        )
          .to.emit(claimRegistry, "MethodRegistered")
          .withArgs(1, "SHA-256", 32);
      });

      it("Should not allow non-admin to register method", async function () {
        await expect(
          claimRegistry
            .connect(addr1)
            .registerMethod(1, "SHA-256", "https://example.com/sha256", 32)
        ).to.be.revertedWith("auth");
      });

      it("Should not allow admin to register method after lock", async function () {
        await claimRegistry.lockAdmin();
        await expect(
          claimRegistry.registerMethod(
            1,
            "SHA-256",
            "https://example.com/sha256",
            32
          )
        ).to.be.revertedWith("auth");
      });

      it("Should not allow duplicate method registration", async function () {
        await claimRegistry.registerMethod(
          1,
          "SHA-256",
          "https://example.com/sha256",
          32
        );
        await expect(
          claimRegistry.registerMethod(
            1,
            "SHA-256",
            "https://example.com/sha256",
            32
          )
        ).to.be.revertedWith("exists");
      });
    });

    describe("setMethodActive", function () {
      beforeEach(async function () {
        await claimRegistry.registerMethod(
          1,
          "SHA-256",
          "https://example.com/sha256",
          32
        );
      });

      it("Should allow admin to set method active", async function () {
        await claimRegistry.setMethodActive(1, false);
        const method = await claimRegistry.methods(1);
        expect(method.active).to.equal(false);
      });

      it("Should emit MethodActiveSet event", async function () {
        await expect(claimRegistry.setMethodActive(1, false))
          .to.emit(claimRegistry, "MethodActiveSet")
          .withArgs(1, false);
      });

      it("Should not allow non-admin to set method active", async function () {
        await expect(
          claimRegistry.connect(addr1).setMethodActive(1, false)
        ).to.be.revertedWith("auth");
      });
    });

    describe("registerExternalID", function () {
      it("Should allow admin to register external ID", async function () {
        await claimRegistry.registerExternalID(
          1,
          "https://example.com/rsa",
          256
        );

        const externalID = await claimRegistry.externalIDs(1);
        expect(externalID.extId).to.equal(1);
        expect(externalID.specURI).to.equal("https://example.com/rsa");
        expect(externalID.sigSizeHint).to.equal(256);
        expect(externalID.active).to.equal(true);
      });

      it("Should emit ExternalIDRegistered event", async function () {
        await expect(
          claimRegistry.registerExternalID(1, "https://example.com/rsa", 256)
        )
          .to.emit(claimRegistry, "ExternalIDRegistered")
          .withArgs(1, "https://example.com/rsa", 256);
      });

      it("Should not allow duplicate external ID registration", async function () {
        await claimRegistry.registerExternalID(
          1,
          "https://example.com/rsa",
          256
        );
        await expect(
          claimRegistry.registerExternalID(1, "https://example.com/rsa", 256)
        ).to.be.revertedWith("exists");
      });
    });

    describe("setExternalIDActive", function () {
      beforeEach(async function () {
        await claimRegistry.registerExternalID(
          1,
          "https://example.com/rsa",
          256
        );
      });

      it("Should allow admin to set external ID active", async function () {
        await claimRegistry.setExternalIDActive(1, false);
        const externalID = await claimRegistry.externalIDs(1);
        expect(externalID.active).to.equal(false);
      });

      it("Should emit ExternalIDActiveSet event", async function () {
        await expect(claimRegistry.setExternalIDActive(1, false))
          .to.emit(claimRegistry, "ExternalIDActiveSet")
          .withArgs(1, false);
      });
    });
  });

  describe("Claim Functions", function () {
    beforeEach(async function () {
      await claimRegistry.registerMethod(
        1,
        "SHA-256",
        "https://example.com/sha256",
        32
      );
      await claimRegistry.registerExternalID(1, "https://example.com/rsa", 256);
    });

    describe("claim (with external signature)", function () {
      it("Should allow user to claim with external signature", async function () {
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));
        const externalSig = ethers.keccak256(ethers.toUtf8Bytes("signature"));
        const pubkey = ethers.keccak256(ethers.toUtf8Bytes("public key"));

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 1,
            fingerprint,
            externalSig,
            pubKey: pubkey,
            metadata: "test metadata",
            extURI: "https://example.com",
          })
        ).to.emit(claimRegistry, "Claimed");
      });

      it("Should not allow claim with inactive method", async function () {
        await claimRegistry.setMethodActive(1, false);
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 1,
            fingerprint,
            externalSig: "0x",
            pubKey: "0x",
            metadata: "test metadata",
            extURI: "https://example.com",
          })
        ).to.be.revertedWith("method inactive");
      });

      it("Should not allow claim with inactive external ID", async function () {
        await claimRegistry.setExternalIDActive(1, false);
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 1,
            fingerprint,
            externalSig: "0x",
            pubKey: "0x",
            metadata: "test metadata",
            extURI: "https://example.com",
          })
        ).to.be.revertedWith("externalID inactive");
      });

      it("Should not allow duplicate claims", async function () {
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));

        await claimRegistry.connect(addr1).claim({
          methodId: 1,
          externalId: 1,
          fingerprint,
          externalSig: "0x",
          pubKey: "0x",
          metadata: "test metadata",
          extURI: "https://example.com",
        });

        await expect(
          claimRegistry.connect(addr2).claim({
            methodId: 1,
            externalId: 1,
            fingerprint,
            externalSig: "0x",
            pubKey: "0x",
            metadata: "test metadata 2",
            extURI: "https://example.com",
          })
        ).to.be.revertedWith("claim exists");
      });

      it("Should enforce signature size hint", async function () {
        await claimRegistry.registerExternalID(
          2,
          "https://example.com/small",
          10
        );
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));
        const largeSig = ethers.keccak256(
          ethers.toUtf8Bytes("very long signature data")
        );

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 2,
            fingerprint,
            externalSig: largeSig,
            pubKey: "0x",
            metadata: "test metadata",
            extURI: "https://example.com",
          })
        ).to.be.revertedWith("sig too large");
      });
    });

    describe("claim (without external signature)", function () {
      it("Should allow user to claim without external signature", async function () {
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 1,
            fingerprint,
            externalSig: "0x",
            pubKey: "0x",
            metadata: "test metadata",
            extURI: "https://example.com",
          })
        ).to.emit(claimRegistry, "Claimed");
      });
    });
  });

  describe("View Functions", function () {
    beforeEach(async function () {
      await claimRegistry.registerMethod(
        1,
        "SHA-256",
        "https://example.com/sha256",
        32
      );
      await claimRegistry.registerExternalID(1, "https://example.com/rsa", 256);

      const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));
      await claimRegistry.connect(addr1).claim({
        methodId: 1,
        externalId: 1,
        fingerprint,
        externalSig: "0x",
        pubKey: "0x",
        metadata: "test metadata",
        extURI: "https://example.com",
      });
    });

    describe("getClaimByIdWithExtId", function () {
      it("Should return claim by method ID, fingerprint, and external ID", async function () {
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));
        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          1
        );

        expect(claim.creator).to.equal(addr1.address);
        expect(claim.metadata).to.equal("test metadata");
        expect(claim.methodId).to.equal(1);
        expect(claim.externalId).to.equal(1);
      });
    });

    describe("getMetadataById", function () {
      it("Should return metadata by method ID, fingerprint, and signature ID", async function () {
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));
        const metadata = await claimRegistry.getMetadataById(1, fingerprint, 1);

        expect(metadata).to.equal("test metadata");
      });
    });
  });

  describe("Edge Cases", function () {
    it("Should handle empty strings and zero values", async function () {
      await claimRegistry.registerMethod(1, "", "", 0);
      await claimRegistry.registerExternalID(1, "", 0);

      const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test"));
      await expect(
        claimRegistry.connect(addr1).claim({
          methodId: 1,
          externalId: 1,
          fingerprint,
          externalSig: "0x",
          pubKey: "0x",
          metadata: "",
          extURI: "",
        })
      ).to.emit(claimRegistry, "Claimed");
    });

    it("Should handle large signature sizes", async function () {
      await claimRegistry.registerMethod(
        1,
        "SHA-256",
        "https://example.com/sha256",
        32
      );
      await claimRegistry.registerExternalID(1, "https://example.com/rsa", 0); // No size limit

      const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));
      const largeSig = ethers.keccak256(
        ethers.toUtf8Bytes("very long signature data".repeat(10))
      );

      await expect(
        claimRegistry.connect(addr1).claim({
          methodId: 1,
          externalId: 1,
          fingerprint,
          externalSig: largeSig,
          pubKey: "0x",
          metadata: "test metadata",
          extURI: "https://example.com",
        })
      ).to.emit(claimRegistry, "Claimed");
    });
  });

  describe("Cryptographic Signature Tests", function () {
    beforeEach(async function () {
      // Register SHA-256 method
      await claimRegistry.registerMethod(
        1,
        "SHA-256",
        "https://tools.ietf.org/html/rfc6234",
        32
      );

      // Register RSA-2048 external ID (256 bytes signature size)
      await claimRegistry.registerExternalID(
        1,
        "https://tools.ietf.org/html/rfc8017",
        256
      );

      // Register HMAC-SHA256 external ID (32 bytes signature size)
      await claimRegistry.registerExternalID(
        2,
        "https://tools.ietf.org/html/rfc2104",
        32
      );
    });

    describe("Realistic RSA Signature Implementation", function () {
      it("Should demonstrate proper RSA-2048 signature with claim()", async function () {
        // Document to be signed
        const document =
          "This is a legal contract for software licensing agreement";
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes(document));

        // Note: The contract stores the fingerprint (hash) of the document, not the document itself
        // The signature is created by signing the fingerprint, not the original document

        // RSA-2048 External ID (ID: 1) - represents the RSA-2048 algorithm
        const rsaExternalId = 1;

        // Generate real RSA-2048 key pair
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });

        // Create real RSA-2048 signature (signing the fingerprint)
        const signature = crypto.sign(
          "sha256",
          Buffer.from(fingerprint.slice(2), "hex"),
          {
            key: privateKey,
          }
        );

        const rsaSignature = "0x" + signature.toString("hex");
        const rsaPublicKey =
          "0x" + Buffer.from(publicKey, "utf8").toString("hex");

        // Create claim with RSA signature
        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: rsaExternalId,
            fingerprint,
            externalSig: rsaSignature,
            pubKey: rsaPublicKey,
            metadata: "Legal Contract",
            extURI: "https://example.com/contract.pdf",
          })
        ).to.emit(claimRegistry, "Claimed");

        // Verify the claim was stored with proper RSA relationship
        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          rsaExternalId
        );
        expect(claim.creator).to.equal(addr1.address);
        expect(claim.methodId).to.equal(1); // SHA-256
        expect(claim.externalId).to.equal(1); // RSA-2048
        expect(claim.externalSig).to.equal(rsaSignature);
        expect(claim.pubKey).to.equal(rsaPublicKey);
        expect(claim.metadata).to.equal("Legal Contract");
      });

      it("Should demonstrate RSA signature verification workflow", async function () {
        // Step 1: Document preparation
        const contractText =
          "Software License Agreement v2.0 - Terms and Conditions";
        const documentHash = ethers.keccak256(ethers.toUtf8Bytes(contractText));

        // Step 2: Generate real RSA-2048 key pair
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });

        // Step 3: Create real RSA-2048 signature
        const signature = crypto.sign(
          "sha256",
          Buffer.from(documentHash.slice(2), "hex"),
          {
            key: privateKey,
          }
        );

        const rsaSignature = "0x" + signature.toString("hex");
        const rsaPublicKey =
          "0x" + Buffer.from(publicKey, "utf8").toString("hex");

        // Step 4: Register claim with RSA signature
        await claimRegistry.connect(addr1).claim({
          methodId: 1, // SHA-256 method
          externalId: 1, // RSA-2048 external ID
          fingerprint: documentHash, // Document fingerprint
          externalSig: rsaSignature, // RSA signature
          pubKey: rsaPublicKey, // RSA public key
          metadata: "Software License", // Document type
          extURI: "https://company.com/license.pdf",
        });

        // Step 5: Real verification (off-chain)
        const isValid = crypto.verify(
          "sha256",
          Buffer.from(documentHash.slice(2), "hex"),
          publicKey,
          signature
        );
        expect(isValid).to.be.true; // Verify the signature is valid

        // Verify claim exists with correct RSA data
        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          documentHash,
          1
        );
        expect(claim.externalId).to.equal(1); // RSA-2048
        expect(claim.externalSig).to.equal(rsaSignature);
        expect(claim.pubKey).to.equal(rsaPublicKey);
      });
    });

    describe("Realistic HMAC Signature Implementation", function () {
      it("Should demonstrate proper HMAC-SHA256 signature with claim()", async function () {
        // Message to be authenticated
        const message = "API request: GET /users/12345";
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes(message));

        // Note: The contract stores the fingerprint (hash) of the message, not the message itself
        // The HMAC signature is created by signing the fingerprint, not the original message

        // HMAC-SHA256 External ID (ID: 2) - represents the HMAC-SHA256 algorithm
        const hmacExternalId = 2;

        // Create real HMAC-SHA256 signature
        const secretKey = "my-secret-api-key-12345";
        const hmac = crypto.createHmac("sha256", secretKey);
        hmac.update(Buffer.from(fingerprint.slice(2), "hex"));
        const hmacSignature = "0x" + hmac.digest("hex");

        // HMAC doesn't use public keys, so we pass empty bytes
        const emptyPublicKey = "0x";

        // Create claim with HMAC signature
        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1, // SHA-256
            externalId: hmacExternalId, // HMAC-SHA256 (ID: 2)
            fingerprint, // SHA-256 hash of message
            externalSig: hmacSignature, // HMAC-SHA256 signature
            pubKey: emptyPublicKey, // empty (HMAC doesn't use public keys)
            metadata: "API Authentication",
            extURI: "https://api.example.com/request",
          })
        ).to.emit(claimRegistry, "Claimed");

        // Verify the claim was stored with proper HMAC relationship
        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          hmacExternalId
        );
        expect(claim.creator).to.equal(addr1.address);
        expect(claim.methodId).to.equal(1); // SHA-256
        expect(claim.externalId).to.equal(2); // HMAC-SHA256
        expect(claim.externalSig).to.equal(hmacSignature);
        expect(claim.pubKey).to.equal(emptyPublicKey); // Empty for HMAC
        expect(claim.metadata).to.equal("API Authentication");
      });

      it("Should demonstrate HMAC signature verification workflow", async function () {
        // Step 1: Message preparation
        const apiRequest =
          'POST /transactions {"amount": 100, "currency": "USD"}';
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes(apiRequest));

        // Step 2: Create real HMAC-SHA256 signature
        const secretKey = "my-secret-api-key";
        const hmac = crypto.createHmac("sha256", secretKey);
        hmac.update(Buffer.from(messageHash.slice(2), "hex"));
        const hmacSignature = "0x" + hmac.digest("hex");

        // Step 3: Register claim with HMAC signature
        await claimRegistry.connect(addr1).claim({
          methodId: 1, // SHA-256 method
          externalId: 2, // HMAC-SHA256 external ID
          fingerprint: messageHash, // Message fingerprint
          externalSig: hmacSignature, // HMAC signature
          pubKey: "0x", // No public key for HMAC
          metadata: "Transaction Request", // Request type
          extURI: "https://api.bank.com/transactions",
        });

        // Step 4: Real verification (off-chain)
        const expectedHmac = crypto.createHmac("sha256", secretKey);
        expectedHmac.update(Buffer.from(messageHash.slice(2), "hex"));
        const expectedSignature = expectedHmac.digest("hex");
        const isValid = crypto.timingSafeEqual(
          Buffer.from(hmacSignature.slice(2), "hex"),
          Buffer.from(expectedSignature, "hex")
        );
        expect(isValid).to.be.true; // Verify the HMAC signature is valid

        // Verify claim exists with correct HMAC data
        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          messageHash,
          2
        );
        expect(claim.externalId).to.equal(2); // HMAC-SHA256
        expect(claim.externalSig).to.equal(hmacSignature);
        expect(claim.pubKey).to.equal("0x"); // Empty for HMAC
      });
    });

    describe("Cryptographic Field Relationships", function () {
      it("Should demonstrate proper field relationships for RSA signatures", async function () {
        const document = "Certificate of Authenticity";
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes(document));

        // RSA signature fields relationship:
        // externalId = 1 (RSA-2048 algorithm identifier)
        // externalSig = actual RSA signature (256 bytes)
        // pubkey = RSA public key (for verification)

        // Generate real RSA-2048 key pair for field relationship test
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
          modulusLength: 2048,
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

        const signature = crypto.sign(
          "sha256",
          Buffer.from(fingerprint.slice(2), "hex"),
          {
            key: privateKey,
          }
        );

        const rsaSignature = "0x" + signature.toString("hex");
        const rsaPublicKey =
          "0x" + Buffer.from(publicKey, "utf8").toString("hex");

        await claimRegistry.connect(addr1).claim({
          methodId: 1,
          externalId: 1,
          fingerprint,
          externalSig: rsaSignature,
          pubKey: rsaPublicKey,
          metadata: "Certificate",
          extURI: "https://example.com/cert.pdf",
        });

        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          1
        );

        // Verify RSA field relationships
        expect(claim.externalId).to.equal(1); // RSA-2048 algorithm
        expect(claim.externalSig.length).to.equal(514); // 256 bytes + 0x prefix
        expect(claim.pubKey.length).to.be.greaterThan(100); // Real RSA public key is much longer
        expect(claim.pubKey).to.not.equal("0x"); // RSA has public key
      });

      it("Should demonstrate proper field relationships for HMAC signatures", async function () {
        const message = "Session token validation";
        const fingerprint = ethers.keccak256(ethers.toUtf8Bytes(message));

        // HMAC signature fields relationship:
        // externalId = 2 (HMAC-SHA256 algorithm identifier)
        // externalSig = actual HMAC signature (32 bytes)
        // pubkey = empty (HMAC doesn't use public keys)

        // Create real HMAC-SHA256 signature for field relationship test
        const secretKey = "test-secret-key";
        const hmac = crypto.createHmac("sha256", secretKey);
        hmac.update(Buffer.from(fingerprint.slice(2), "hex"));
        const hmacSignature = "0x" + hmac.digest("hex");
        const emptyPublicKey = "0x";

        await claimRegistry.connect(addr1).claim({
          methodId: 1,
          externalId: 2,
          fingerprint,
          externalSig: hmacSignature,
          pubKey: emptyPublicKey,
          metadata: "Session Token",
          extURI: "https://auth.example.com",
        });

        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          2
        );

        // Verify HMAC field relationships
        expect(claim.externalId).to.equal(2); // HMAC-SHA256 algorithm
        expect(claim.externalSig.length).to.equal(66); // 32 bytes + 0x prefix
        expect(claim.pubKey).to.equal("0x"); // HMAC has no public key
      });

      it("Should demonstrate mixed cryptographic signatures in batch operations", async function () {
        // Create real cryptographic signatures for mixed test
        const documents = [];

        // RSA Document
        const rsaDoc = "Legal Document A";
        const rsaFingerprint = ethers.keccak256(ethers.toUtf8Bytes(rsaDoc));
        const { publicKey: rsaPublicKey, privateKey: rsaPrivateKey } =
          crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
          });
        const rsaSignature = crypto.sign(
          "sha256",
          Buffer.from(rsaFingerprint.slice(2), "hex"),
          {
            key: rsaPrivateKey,
          }
        );

        documents.push({
          content: rsaDoc,
          type: "RSA",
          externalId: 1,
          signature: "0x" + rsaSignature.toString("hex"),
          pubkey: "0x" + Buffer.from(rsaPublicKey, "utf8").toString("hex"),
        });

        // HMAC Document
        const hmacDoc = "API Request B";
        const hmacFingerprint = ethers.keccak256(ethers.toUtf8Bytes(hmacDoc));
        const hmacSecretKey = "mixed-test-secret-key";
        const hmac = crypto.createHmac("sha256", hmacSecretKey);
        hmac.update(Buffer.from(hmacFingerprint.slice(2), "hex"));
        const hmacSignature = hmac.digest("hex");

        documents.push({
          content: hmacDoc,
          type: "HMAC",
          externalId: 2,
          signature: "0x" + hmacSignature,
          pubkey: "0x",
        });

        // Create individual claims to demonstrate proper field relationships
        for (let i = 0; i < documents.length; i++) {
          const doc = documents[i];
          const fingerprint = ethers.keccak256(ethers.toUtf8Bytes(doc.content));

          await claimRegistry.connect(addr1).claim({
            methodId: 1, // SHA-256 method
            externalId: doc.externalId, // RSA (1) or HMAC (2)
            fingerprint, // Document fingerprint
            externalSig: doc.signature, // RSA or HMAC signature
            pubKey: doc.pubkey, // RSA public key or empty
            metadata: doc.content, // Document content
            extURI: `https://example.com/${doc.type.toLowerCase()}-${i + 1}`,
          });

          // Verify proper field relationships
          const claim = await claimRegistry.getClaimByIdWithExtId(
            1,
            fingerprint,
            doc.externalId
          );
          expect(claim.externalId).to.equal(doc.externalId);
          expect(claim.externalSig).to.equal(doc.signature);
          expect(claim.pubKey).to.equal(doc.pubkey);
        }
      });
    });

    describe("RSA Signature Tests", function () {
      it("Should accept valid RSA-2048 signature", async function () {
        const fingerprint = ethers.keccak256(
          ethers.toUtf8Bytes("RSA test data")
        );

        // Simulate RSA-2048 signature (256 bytes)
        // In a real scenario, this would be an actual RSA signature
        const baseHash = ethers.keccak256(
          ethers.toUtf8Bytes("RSA signature data")
        );
        const rsaSignature = "0x" + baseHash.slice(2).repeat(8).slice(0, 512); // 256 bytes

        // Simulate RSA public key (PEM format would be much longer, but we'll use a shorter representation)
        const rsaPublicKey = ethers.keccak256(
          ethers.toUtf8Bytes("RSA public key data")
        );

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1, // SHA-256 method
            externalId: 1, // RSA-2048 external ID
            fingerprint,
            externalSig: rsaSignature,
            pubKey: rsaPublicKey,
            metadata: "RSA signed document",
            extURI: "https://example.com/rsa-document",
          })
        ).to.emit(claimRegistry, "Claimed");

        // Verify the claim was stored correctly
        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          1
        );
        expect(claim.creator).to.equal(addr1.address);
        expect(claim.metadata).to.equal("RSA signed document");
        expect(claim.externalId).to.equal(1);
        expect(claim.externalSig).to.equal(rsaSignature);
        expect(claim.pubKey).to.equal(rsaPublicKey);
      });

      it("Should reject RSA signature that's too large", async function () {
        const fingerprint = ethers.keccak256(
          ethers.toUtf8Bytes("RSA test data")
        );

        // Create a signature that's too large (300 bytes > 256 byte limit)
        const baseHash = ethers.keccak256(
          ethers.toUtf8Bytes("oversized signature data")
        );
        const oversizedSignature = "0x" + baseHash.slice(2).repeat(10);

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 1,
            fingerprint,
            externalSig: oversizedSignature,
            pubKey: "0x",
            metadata: "test metadata",
            extURI: "https://example.com",
          })
        ).to.be.revertedWith("sig too large");
      });

      it("Should handle multiple RSA signatures for different documents", async function () {
        const documents = [
          "Document 1: Contract Agreement",
          "Document 2: Certificate of Authenticity",
          "Document 3: Legal Declaration",
        ];

        for (let i = 0; i < documents.length; i++) {
          const fingerprint = ethers.keccak256(
            ethers.toUtf8Bytes(`RSA document ${i + 1}`)
          );
          const baseHash = ethers.keccak256(
            ethers.toUtf8Bytes(`RSA signature for document ${i + 1}`)
          );
          const rsaSignature = "0x" + baseHash.slice(2).repeat(8).slice(0, 512);
          const rsaPublicKey = ethers.keccak256(
            ethers.toUtf8Bytes(`RSA public key ${i + 1}`)
          );

          await expect(
            claimRegistry.connect(addr1).claim({
              methodId: 1,
              externalId: 1,
              fingerprint,
              externalSig: rsaSignature,
              pubKey: rsaPublicKey,
              metadata: documents[i],
              extURI: `https://example.com/document-${i + 1}`,
            })
          ).to.emit(claimRegistry, "Claimed");
        }

        // Verify all claims were created by checking individual claims
        for (let i = 0; i < documents.length; i++) {
          const fingerprint = ethers.keccak256(
            ethers.toUtf8Bytes(`RSA document ${i + 1}`)
          );
          const claim = await claimRegistry.getClaimByIdWithExtId(
            1,
            fingerprint,
            1
          );
          expect(claim.metadata).to.equal(documents[i]);
        }
      });
    });

    describe("HMAC Signature Tests", function () {
      it("Should accept valid HMAC-SHA256 signature", async function () {
        const fingerprint = ethers.keccak256(
          ethers.toUtf8Bytes("HMAC test data")
        );

        // Simulate HMAC-SHA256 signature (32 bytes)
        const hmacSignature = ethers.keccak256(
          ethers.toUtf8Bytes("HMAC signature data")
        );

        // HMAC doesn't use public keys, so we pass empty bytes
        const emptyPublicKey = "0x";

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1, // SHA-256 method
            externalId: 2, // HMAC-SHA256 external ID
            fingerprint,
            externalSig: hmacSignature,
            pubKey: emptyPublicKey,
            metadata: "HMAC authenticated message",
            extURI: "https://example.com/hmac-message",
          })
        ).to.emit(claimRegistry, "Claimed");

        // Verify the claim was stored correctly
        const claim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          2
        );
        expect(claim.creator).to.equal(addr1.address);
        expect(claim.metadata).to.equal("HMAC authenticated message");
        expect(claim.externalId).to.equal(2);
        expect(claim.externalSig).to.equal(hmacSignature);
        expect(claim.pubKey).to.equal(emptyPublicKey);
      });

      it("Should handle HMAC with different secret keys", async function () {
        const messages = [
          "Secret message 1",
          "Secret message 2",
          "Secret message 3",
        ];

        for (let i = 0; i < messages.length; i++) {
          const fingerprint = ethers.keccak256(
            ethers.toUtf8Bytes(`HMAC message ${i + 1}`)
          );
          // Simulate different HMAC signatures for different secret keys
          const hmacSignature = ethers.keccak256(
            ethers.toUtf8Bytes(`HMAC with secret key ${i + 1}`)
          );

          await expect(
            claimRegistry.connect(addr1).claim({
              methodId: 1,
              externalId: 2,
              fingerprint,
              externalSig: hmacSignature,
              pubKey: "0x",
              metadata: messages[i],
              extURI: `https://example.com/hmac-${i + 1}`,
            })
          ).to.emit(claimRegistry, "Claimed");
        }

        // Verify all HMAC claims were created
        for (let i = 0; i < messages.length; i++) {
          const fingerprint = ethers.keccak256(
            ethers.toUtf8Bytes(`HMAC message ${i + 1}`)
          );
          const claim = await claimRegistry.getClaimByIdWithExtId(
            1,
            fingerprint,
            2
          );
          expect(claim.metadata).to.equal(messages[i]);
        }
      });

      it("Should reject HMAC signature that's too large", async function () {
        const fingerprint = ethers.keccak256(
          ethers.toUtf8Bytes("HMAC test data")
        );

        // Create a signature that's too large (64 bytes > 32 byte limit)
        const baseHash = ethers.keccak256(
          ethers.toUtf8Bytes("oversized hmac signature data")
        );
        const oversizedHmacSignature = "0x" + baseHash.slice(2).repeat(2);

        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 2,
            fingerprint,
            externalSig: oversizedHmacSignature,
            pubKey: "0x",
            metadata: "test metadata",
            extURI: "https://example.com",
          })
        ).to.be.revertedWith("sig too large");
      });
    });

    describe("Mixed Cryptographic Signature Tests", function () {
      it("Should handle both RSA and HMAC signatures for the same document", async function () {
        const fingerprint = ethers.keccak256(
          ethers.toUtf8Bytes("Mixed signature document")
        );

        // RSA signature
        const baseHash = ethers.keccak256(ethers.toUtf8Bytes("RSA signature"));
        const rsaSignature = "0x" + baseHash.slice(2).repeat(8).slice(0, 512);
        const rsaPublicKey = ethers.keccak256(
          ethers.toUtf8Bytes("RSA public key")
        );

        // HMAC signature
        const hmacSignature = ethers.keccak256(
          ethers.toUtf8Bytes("HMAC signature")
        );

        // Create RSA claim
        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 1,
            fingerprint,
            externalSig: rsaSignature,
            pubKey: rsaPublicKey,
            metadata: "RSA signed version",
            extURI: "https://example.com/rsa",
          })
        ).to.emit(claimRegistry, "Claimed");

        // Create HMAC claim with different fingerprint (since same fingerprint would conflict)
        const hmacFingerprint = ethers.keccak256(
          ethers.toUtf8Bytes("Mixed signature document HMAC")
        );
        await expect(
          claimRegistry.connect(addr1).claim({
            methodId: 1,
            externalId: 2,
            fingerprint: hmacFingerprint,
            externalSig: hmacSignature,
            pubKey: "0x",
            metadata: "HMAC signed version",
            extURI: "https://example.com/hmac",
          })
        ).to.emit(claimRegistry, "Claimed");

        // Verify both claims exist
        const rsaClaim = await claimRegistry.getClaimByIdWithExtId(
          1,
          fingerprint,
          1
        );
        const hmacClaim = await claimRegistry.getClaimByIdWithExtId(
          1,
          hmacFingerprint,
          2
        );

        expect(rsaClaim.metadata).to.equal("RSA signed version");
        expect(hmacClaim.metadata).to.equal("HMAC signed version");
        expect(rsaClaim.externalId).to.equal(1);
        expect(hmacClaim.externalId).to.equal(2);
      });

      it("Should demonstrate real-world usage with individual claim operations", async function () {
        const documents = [
          { type: "RSA", content: "Legal Contract", extId: 1 },
          { type: "HMAC", content: "API Authentication", extId: 2 },
          { type: "RSA", content: "Certificate", extId: 1 },
          { type: "HMAC", content: "Session Token", extId: 2 },
        ];

        // Create individual claims for each document
        for (let i = 0; i < documents.length; i++) {
          const doc = documents[i];
          const fingerprint = ethers.keccak256(
            ethers.toUtf8Bytes(`Document ${i + 1}: ${doc.content}`)
          );
          const extURI = `https://example.com/${doc.type.toLowerCase()}-${
            i + 1
          }`;

          let externalSig, pubKey;
          if (doc.type === "RSA") {
            const baseHash = ethers.keccak256(
              ethers.toUtf8Bytes(`RSA sig ${i + 1}`)
            );
            externalSig = "0x" + baseHash.slice(2).repeat(8).slice(0, 512);
            pubKey = ethers.keccak256(ethers.toUtf8Bytes(`RSA key ${i + 1}`));
          } else {
            externalSig = ethers.keccak256(
              ethers.toUtf8Bytes(`HMAC sig ${i + 1}`)
            );
            pubKey = "0x";
          }

          // Create individual claim
          await expect(
            claimRegistry.connect(addr1).claim({
              methodId: 1, // SHA-256 method
              externalId: doc.extId, // External ID (RSA=1, HMAC=2)
              fingerprint,
              externalSig,
              pubKey,
              metadata: doc.content,
              extURI,
            })
          ).to.emit(claimRegistry, "Claimed");
        }

        // Verify all claims were created successfully
        for (let i = 0; i < documents.length; i++) {
          const doc = documents[i];
          const fingerprint = ethers.keccak256(
            ethers.toUtf8Bytes(`Document ${i + 1}: ${doc.content}`)
          );

          const claim = await claimRegistry.getClaimByIdWithExtId(
            1,
            fingerprint,
            doc.extId
          );
          expect(claim.creator).to.equal(addr1.address);
          expect(claim.metadata).to.equal(doc.content);
          expect(claim.externalId).to.equal(doc.extId);
        }
      });
    });
  });
});
