const { ethers } = require("hardhat");

async function main() {
  const factoryAddress =
    process.env.FACTORY_ADDRESS || "0xE0CcFa6DebD5be29C6DE792583B6dBAab2eD41E4"; // GTN factory address

  if (!factoryAddress) {
    console.error("Please set FACTORY_ADDRESS environment variable");
    process.exit(1);
  }

  const name = process.env.REGISTRY_NAME || "My Registry";
  const description = process.env.REGISTRY_DESCRIPTION || "https://ucfr.io";

  console.log("Creating new registry through factory...");
  console.log("Factory address:", factoryAddress);
  console.log("Registry name:", name);
  console.log("Registry description:", description);

  // Get the factory contract
  const factory = await ethers.getContractAt(
    "ClaimRegistryFactory",
    factoryAddress
  );

  // Create the registry
  const tx = await factory.createRegistry(name, description);
  console.log("Transaction hash:", tx.hash);

  // Wait for the transaction to be mined
  const receipt = await tx.wait();
  console.log("Transaction confirmed in block:", receipt.blockNumber);

  // Get the registry address from the event
  const event = receipt.logs.find((log) => {
    try {
      const parsed = factory.interface.parseLog(log);
      return parsed.name === "RegistryCreated";
    } catch (e) {
      return false;
    }
  });

  if (event) {
    const registryAddress = event.args.registryAddress;
    const creator = event.args.creator;
    const registryId = event.args.registryId;

    console.log("\n✓ Registry created successfully!");
    console.log("Registry address:", registryAddress);
    console.log("Creator:", creator);
    console.log("Registry ID:", registryId.toString());

    // Get registry info
    const registryInfo = await factory.getRegistryInfo(registryAddress);
    console.log("\nRegistry Info:");
    console.log("- Name:", registryInfo.name);
    console.log("- Description:", registryInfo.description);
    console.log(
      "- Created at:",
      new Date(Number(registryInfo.createdAt) * 1000).toISOString()
    );
    console.log("- Active:", registryInfo.active);

    // Get the registry contract instance
    const registry = await ethers.getContractAt(
      "GeneralizedClaimRegistry",
      registryAddress
    );
    console.log("\nRegistry Admin:", await registry.admin());
    console.log("Admin Locked:", await registry.adminLocked());

    console.log("\nNext steps:");
    console.log("1. Register methods in your registry");
    console.log("2. Register external IDs");
    console.log("3. Start making claims using claim({ ... })!");

    return {
      registryAddress,
      registry,
      registryInfo,
    };
  } else {
    console.error(
      "Could not find RegistryCreated event in transaction receipt"
    );
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
