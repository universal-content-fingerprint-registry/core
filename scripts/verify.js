const { ethers } = require("hardhat");

async function main() {
  const contractAddress = process.env.CONTRACT_ADDRESS;
  const contractType = process.env.CONTRACT_TYPE || "factory"; // "factory" or "registry"
  
  if (!contractAddress) {
    console.error("Please set CONTRACT_ADDRESS environment variable");
    process.exit(1);
  }

  console.log("Verifying contract at:", contractAddress);
  console.log("Contract type:", contractType);

  try {
    if (contractType === "factory") {
      // Verify Factory contract
      const factory = await ethers.getContractAt("ClaimRegistryFactory", contractAddress);
      
      const owner = await factory.owner();
      const totalRegistries = await factory.totalRegistries();
      
      console.log("✓ Factory contract is deployed and accessible");
      console.log("Factory owner:", owner);
      console.log("Total registries created:", totalRegistries.toString());
      
      // Get all registries
      const allRegistries = await factory.getAllRegistries();
      console.log("All registries:", allRegistries);
      
      if (allRegistries.length > 0) {
        console.log("\nRegistry details:");
        for (let i = 0; i < Math.min(allRegistries.length, 5); i++) {
          const registryInfo = await factory.getRegistryInfo(allRegistries[i]);
          console.log(`- Registry ${i + 1}: ${registryInfo.name} (${allRegistries[i]})`);
        }
        if (allRegistries.length > 5) {
          console.log(`... and ${allRegistries.length - 5} more registries`);
        }
      }
      
    } else if (contractType === "registry") {
      // Verify Registry contract
      const registry = await ethers.getContractAt("GeneralizedClaimRegistry", contractAddress);
      
      const admin = await registry.admin();
      const adminLocked = await registry.adminLocked();
      
      console.log("✓ Registry contract is deployed and accessible");
      console.log("Admin address:", admin);
      console.log("Admin locked:", adminLocked);

      // Check if any methods are registered
      try {
        const method1 = await registry.methods(1);
        if (method1.fpSizeBytes > 0) {
          console.log("✓ Method 1 registered:", method1.name);
        }
      } catch (error) {
        console.log("No methods registered yet");
      }

      // Check if any external IDs are registered
      try {
        const extId1 = await registry.externalIDs(1);
        if (extId1.extId > 0) {
          console.log("✓ External ID 1 registered");
        }
      } catch (error) {
        console.log("No external IDs registered yet");
      }
    } else {
      console.error("Invalid contract type. Use 'factory' or 'registry'");
      process.exit(1);
    }

    console.log("\n✓ Contract verification completed successfully!");

  } catch (error) {
    console.error("Contract verification failed:", error.message);
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
