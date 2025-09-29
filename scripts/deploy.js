const { ethers } = require("hardhat");

async function main() {
  console.log("Deploying ClaimRegistryFactory...");

  // Get the contract factory
  const ClaimRegistryFactory = await ethers.getContractFactory(
    "ClaimRegistryFactory"
  );

  // Deploy the factory contract
  const factory = await ClaimRegistryFactory.deploy();

  // Wait for deployment to finish
  await factory.waitForDeployment();

  const factoryAddress = await factory.getAddress();
  console.log("ClaimRegistryFactory deployed to:", factoryAddress);

  // Get the deployer account
  const [deployer] = await ethers.getSigners();
  console.log("Deployed by:", deployer.address);

  // Verify deployment
  console.log("Total registries:", await factory.totalRegistries());

  // Optional: Create sample registries for testing
  if (process.env.INITIALIZE === "true") {
    console.log("\nCreating sample registries...");

    try {
      // Create a sample registry
      const tx = await factory.createRegistry(
        "Sample Registry",
        "A sample registry for testing purposes"
      );
      const receipt = await tx.wait();

      const event = receipt.logs.find((log) => {
        try {
          const parsed = factory.interface.parseLog(log);
          return parsed.name === "RegistryCreated";
        } catch (e) {
          return false;
        }
      });

      const sampleRegistryAddress = event.args.registryAddress;
      console.log("✓ Created sample registry at:", sampleRegistryAddress);

      // Get the registry contract instance
      const sampleRegistry = await ethers.getContractAt(
        "GeneralizedClaimRegistry",
        sampleRegistryAddress
      );

      // Register some methods in the sample registry
      await sampleRegistry.registerMethod(
        0,
        "SHA-256",
        "https://tools.ietf.org/html/rfc6234",
        32
      );
      console.log("✓ Registered SHA-256 method in sample registry");

      await sampleRegistry.registerMethod(
        1,
        "MD5",
        "https://tools.ietf.org/html/rfc1321",
        16
      );
      console.log("✓ Registered MD5 method in sample registry");

      // Register external IDs
      await sampleRegistry.registerExternalID(
        0,
        "https://tools.ietf.org/html/rfc8017",
        256
      );
      console.log("✓ Registered RSA-2048 external ID in sample registry");

      await sampleRegistry.registerExternalID(
        1,
        "https://tools.ietf.org/html/rfc6979",
        64
      );
      console.log("✓ Registered ECDSA external ID in sample registry");

      // Optionally create a sample claim
      const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("sample data"));
      await sampleRegistry.claim({
        methodId: 0,
        externalId: 1,
        fingerprint,
        externalSig: "0x",
        pubKey: "0x",
        metadata: "Sample claim",
        extURI: "https://example.com/sample",
      });

      console.log("\n✓ Sample registry initialization complete!");
    } catch (error) {
      console.error("Error during initialization:", error.message);
    }
  }

  console.log("\nDeployment completed successfully!");
  console.log("\nNext steps:");
  console.log("1. Copy the factory address above");
  console.log("2. Verify the contract on Etherscan (if on mainnet/testnet)");
  console.log("3. Use the factory to create new registries");
  console.log("4. Register methods and external IDs in your registries");
  console.log("5. Start making claims!");

  return {
    factoryAddress,
    factory,
  };
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
