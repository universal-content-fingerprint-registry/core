const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ClaimRegistryFactory", function () {
  let factory;
  let owner;
  let addr1;
  let addr2;
  let addrs;

  beforeEach(async function () {
    [owner, addr1, addr2, ...addrs] = await ethers.getSigners();

    const ClaimRegistryFactory = await ethers.getContractFactory(
      "ClaimRegistryFactory"
    );
    factory = await ClaimRegistryFactory.deploy();
    await factory.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      expect(await factory.owner()).to.equal(owner.address);
    });

    it("Should initialize with zero total registries", async function () {
      expect(await factory.totalRegistries()).to.equal(0);
    });

    it("Should return empty arrays initially", async function () {
      expect(await factory.getAllRegistries()).to.deep.equal([]);
      expect(await factory.getRegistriesByCreator(addr1.address)).to.deep.equal(
        []
      );
    });
  });

  describe("createRegistry", function () {
    it("Should create a new registry successfully", async function () {
      const name = "Test Registry";
      const description = "A test registry for testing purposes";

      const tx = await factory.connect(addr1).createRegistry(name, description);
      await expect(tx)
        .to.emit(factory, "RegistryCreated")
        .withArgs(
          await factory.registryById(0),
          addr1.address,
          0,
          name,
          description
        );

      expect(await factory.totalRegistries()).to.equal(1);

      const registryAddress = await factory.registryById(0);
      const registryInfo = await factory.getRegistryInfo(registryAddress);

      expect(registryInfo.registryAddress).to.equal(registryAddress);
      expect(registryInfo.creator).to.equal(addr1.address);
      expect(registryInfo.name).to.equal(name);
      expect(registryInfo.description).to.equal(description);
      expect(registryInfo.active).to.equal(true);
      expect(registryInfo.createdAt).to.be.greaterThan(0);
    });

    it("Should track registries by creator", async function () {
      await factory
        .connect(addr1)
        .createRegistry("Registry 1", "Description 1");
      await factory
        .connect(addr1)
        .createRegistry("Registry 2", "Description 2");
      await factory
        .connect(addr2)
        .createRegistry("Registry 3", "Description 3");

      const addr1Registries = await factory.getRegistriesByCreator(
        addr1.address
      );
      const addr2Registries = await factory.getRegistriesByCreator(
        addr2.address
      );

      expect(addr1Registries.length).to.equal(2);
      expect(addr2Registries.length).to.equal(1);
    });

    it("Should maintain all registries array", async function () {
      await factory
        .connect(addr1)
        .createRegistry("Registry 1", "Description 1");
      await factory
        .connect(addr2)
        .createRegistry("Registry 2", "Description 2");

      const allRegistries = await factory.getAllRegistries();
      expect(allRegistries.length).to.equal(2);
    });

    it("Should return the correct registry address", async function () {
      const tx = await factory
        .connect(addr1)
        .createRegistry("Test", "Test Description");
      const receipt = await tx.wait();

      // Get the registry address from the event
      const event = receipt.logs.find((log) => {
        try {
          const parsed = factory.interface.parseLog(log);
          return parsed.name === "RegistryCreated";
        } catch (e) {
          return false;
        }
      });

      const registryAddress = event.args.registryAddress;
      expect(await factory.doesRegistryExist(registryAddress)).to.equal(true);
    });

    it("Should create a functional GeneralizedClaimRegistry", async function () {
      const tx = await factory
        .connect(addr1)
        .createRegistry("Test", "Test Description");
      const receipt = await tx.wait();

      const event = receipt.logs.find((log) => {
        try {
          const parsed = factory.interface.parseLog(log);
          return parsed.name === "RegistryCreated";
        } catch (e) {
          return false;
        }
      });

      const registryAddress = event.args.registryAddress;
      const registry = await ethers.getContractAt(
        "GeneralizedClaimRegistry",
        registryAddress
      );

      // Test that the created registry is functional
      expect(await registry.admin()).to.equal(addr1.address);
      expect(await registry.adminLocked()).to.equal(false);
    });
  });

  describe("createMultipleRegistries", function () {
    it("Should create multiple registries successfully", async function () {
      const names = ["Registry 1", "Registry 2", "Registry 3"];
      const descriptions = ["Description 1", "Description 2", "Description 3"];

      const tx = await factory
        .connect(addr1)
        .createMultipleRegistries(names, descriptions);
      const receipt = await tx.wait();

      // Get registry addresses from events
      const registryAddresses = [];
      for (const log of receipt.logs) {
        try {
          const parsed = factory.interface.parseLog(log);
          if (parsed.name === "RegistryCreated") {
            registryAddresses.push(parsed.args.registryAddress);
          }
        } catch (e) {
          // Skip logs that can't be parsed
        }
      }

      expect(registryAddresses.length).to.equal(3);
      expect(await factory.totalRegistries()).to.equal(3);

      for (let i = 0; i < 3; i++) {
        const registryInfo = await factory.getRegistryInfo(
          registryAddresses[i]
        );
        expect(registryInfo.name).to.equal(names[i]);
        expect(registryInfo.description).to.equal(descriptions[i]);
        expect(registryInfo.creator).to.equal(addr1.address);
      }
    });

    it("Should revert on array length mismatch", async function () {
      const names = ["Registry 1", "Registry 2"];
      const descriptions = ["Description 1"];

      await expect(
        factory.connect(addr1).createMultipleRegistries(names, descriptions)
      ).to.be.revertedWith("Arrays length mismatch");
    });

    it("Should revert on empty arrays", async function () {
      const names = [];
      const descriptions = [];

      await expect(
        factory.connect(addr1).createMultipleRegistries(names, descriptions)
      ).to.be.revertedWith("Empty arrays");
    });

    it("Should revert on too many registries", async function () {
      const names = new Array(11).fill("Registry");
      const descriptions = new Array(11).fill("Description");

      await expect(
        factory.connect(addr1).createMultipleRegistries(names, descriptions)
      ).to.be.revertedWith("Too many registries in one transaction");
    });
  });

  describe("Registry Management", function () {
    let registryAddress;

    beforeEach(async function () {
      const tx = await factory
        .connect(addr1)
        .createRegistry("Test Registry", "Test Description");
      const receipt = await tx.wait();

      const event = receipt.logs.find((log) => {
        try {
          const parsed = factory.interface.parseLog(log);
          return parsed.name === "RegistryCreated";
        } catch (e) {
          return false;
        }
      });

      registryAddress = event.args.registryAddress;
    });

    describe("updateRegistryName", function () {
      it("Should update registry name by creator", async function () {
        const newName = "Updated Registry Name";

        await expect(
          factory.connect(addr1).updateRegistryName(registryAddress, newName)
        )
          .to.emit(factory, "RegistryNameUpdated")
          .withArgs(registryAddress, "Test Registry", newName);

        const registryInfo = await factory.getRegistryInfo(registryAddress);
        expect(registryInfo.name).to.equal(newName);
      });

      it("Should not allow non-creator to update name", async function () {
        await expect(
          factory.connect(addr2).updateRegistryName(registryAddress, "New Name")
        ).to.be.revertedWith("Only registry creator can call this function");
      });

      it("Should not allow updating non-existent registry", async function () {
        await expect(
          factory
            .connect(addr1)
            .updateRegistryName(ethers.ZeroAddress, "New Name")
        ).to.be.revertedWith("Registry does not exist");
      });
    });

    describe("updateRegistryDescription", function () {
      it("Should update registry description by creator", async function () {
        const newDescription = "Updated Description";

        await expect(
          factory
            .connect(addr1)
            .updateRegistryDescription(registryAddress, newDescription)
        )
          .to.emit(factory, "RegistryDescriptionUpdated")
          .withArgs(registryAddress, "Test Description", newDescription);

        const registryInfo = await factory.getRegistryInfo(registryAddress);
        expect(registryInfo.description).to.equal(newDescription);
      });

      it("Should not allow non-creator to update description", async function () {
        await expect(
          factory
            .connect(addr2)
            .updateRegistryDescription(registryAddress, "New Description")
        ).to.be.revertedWith("Only registry creator can call this function");
      });
    });

    describe("deactivateRegistry", function () {
      it("Should deactivate registry by creator", async function () {
        await factory.connect(addr1).deactivateRegistry(registryAddress);

        const registryInfo = await factory.getRegistryInfo(registryAddress);
        expect(registryInfo.active).to.equal(false);
      });

      it("Should not allow non-creator to deactivate", async function () {
        await expect(
          factory.connect(addr2).deactivateRegistry(registryAddress)
        ).to.be.revertedWith("Only registry creator can call this function");
      });
    });

    describe("reactivateRegistry", function () {
      beforeEach(async function () {
        await factory.connect(addr1).deactivateRegistry(registryAddress);
      });

      it("Should reactivate registry by creator", async function () {
        await factory.connect(addr1).reactivateRegistry(registryAddress);

        const registryInfo = await factory.getRegistryInfo(registryAddress);
        expect(registryInfo.active).to.equal(true);
      });

      it("Should not allow non-creator to reactivate", async function () {
        await expect(
          factory.connect(addr2).reactivateRegistry(registryAddress)
        ).to.be.revertedWith("Only registry creator can call this function");
      });
    });
  });

  describe("View Functions", function () {
    let registryAddress1;
    let registryAddress2;

    beforeEach(async function () {
      const tx1 = await factory
        .connect(addr1)
        .createRegistry("Registry 1", "Description 1");
      const receipt1 = await tx1.wait();

      const event1 = receipt1.logs.find((log) => {
        try {
          const parsed = factory.interface.parseLog(log);
          return parsed.name === "RegistryCreated";
        } catch (e) {
          return false;
        }
      });

      registryAddress1 = event1.args.registryAddress;

      const tx2 = await factory
        .connect(addr2)
        .createRegistry("Registry 2", "Description 2");
      const receipt2 = await tx2.wait();

      const event2 = receipt2.logs.find((log) => {
        try {
          const parsed = factory.interface.parseLog(log);
          return parsed.name === "RegistryCreated";
        } catch (e) {
          return false;
        }
      });

      registryAddress2 = event2.args.registryAddress;
    });

    it("Should return correct registry info", async function () {
      const info = await factory.getRegistryInfo(registryAddress1);

      expect(info.registryAddress).to.equal(registryAddress1);
      expect(info.creator).to.equal(addr1.address);
      expect(info.name).to.equal("Registry 1");
      expect(info.description).to.equal("Description 1");
      expect(info.active).to.equal(true);
    });

    it("Should return registries by creator", async function () {
      const addr1Registries = await factory.getRegistriesByCreator(
        addr1.address
      );
      const addr2Registries = await factory.getRegistriesByCreator(
        addr2.address
      );

      expect(addr1Registries).to.include(registryAddress1);
      expect(addr2Registries).to.include(registryAddress2);
    });

    it("Should return all registries", async function () {
      const allRegistries = await factory.getAllRegistries();

      expect(allRegistries).to.include(registryAddress1);
      expect(allRegistries).to.include(registryAddress2);
      expect(allRegistries.length).to.equal(2);
    });

    it("Should return correct registry count by creator", async function () {
      expect(await factory.getRegistryCountByCreator(addr1.address)).to.equal(
        1
      );
      expect(await factory.getRegistryCountByCreator(addr2.address)).to.equal(
        1
      );
      expect(await factory.getRegistryCountByCreator(owner.address)).to.equal(
        0
      );
    });

    it("Should check registry existence correctly", async function () {
      expect(await factory.doesRegistryExist(registryAddress1)).to.equal(true);
      expect(await factory.doesRegistryExist(registryAddress2)).to.equal(true);
      expect(await factory.doesRegistryExist(ethers.ZeroAddress)).to.equal(
        false
      );
    });

    it("Should return registry by ID", async function () {
      expect(await factory.getRegistryById(0)).to.equal(registryAddress1);
      expect(await factory.getRegistryById(1)).to.equal(registryAddress2);
    });

    it("Should revert on invalid registry ID", async function () {
      await expect(factory.getRegistryById(999)).to.be.revertedWith(
        "Registry ID does not exist"
      );
    });
  });

  describe("Admin Functions", function () {
    it("Should transfer ownership", async function () {
      await factory.transferOwnership(addr1.address);
      expect(await factory.owner()).to.equal(addr1.address);
    });

    it("Should not allow non-owner to transfer ownership", async function () {
      await expect(
        factory.connect(addr1).transferOwnership(addr2.address)
      ).to.be.revertedWith("Only owner can call this function");
    });

    it("Should not allow transfer to zero address", async function () {
      await expect(
        factory.transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("New owner cannot be zero address");
    });

    it("Should return factory stats", async function () {
      await factory.connect(addr1).createRegistry("Test", "Test Description");

      const [total, factoryOwner] = await factory.getFactoryStats();
      expect(total).to.equal(1);
      expect(factoryOwner).to.equal(owner.address);
    });
  });

  describe("Integration Tests", function () {
    it("Should work with actual registry operations", async function () {
      // Create a registry through factory
      const tx = await factory
        .connect(addr1)
        .createRegistry("Integration Test", "Testing integration");
      const receipt = await tx.wait();

      const event = receipt.logs.find((log) => {
        try {
          const parsed = factory.interface.parseLog(log);
          return parsed.name === "RegistryCreated";
        } catch (e) {
          return false;
        }
      });

      const registryAddress = event.args.registryAddress;
      const registry = await ethers.getContractAt(
        "GeneralizedClaimRegistry",
        registryAddress
      );

      // Verify the admin is set correctly
      const admin = await registry.admin();
      console.log("Registry admin:", admin);
      console.log("Expected admin (addr1):", addr1.address);

      // Test registry functionality
      await registry
        .connect(addr1)
        .registerMethod(1, "SHA-256", "https://example.com/sha256", 32);
      await registry
        .connect(addr1)
        .registerExternalID(1, "https://example.com/rsa", 256);

      const fingerprint = ethers.keccak256(ethers.toUtf8Bytes("test data"));
      await registry.connect(addr1).claim({
        methodId: 1,
        externalId: 1,
        fingerprint,
        externalSig: "0x",
        pubKey: "0x",
        metadata: "test metadata",
        extURI: "https://example.com",
      });

      // Verify the claim was created
      const claim = await registry.getClaimByIdWithExtId(1, fingerprint, 1);
      expect(claim.creator).to.equal(addr1.address);
      expect(claim.metadata).to.equal("test metadata");
    });

    it("Should handle multiple creators and registries", async function () {
      // Create registries by different creators
      await factory
        .connect(addr1)
        .createRegistry("Registry 1", "Description 1");
      await factory
        .connect(addr1)
        .createRegistry("Registry 2", "Description 2");
      await factory
        .connect(addr2)
        .createRegistry("Registry 3", "Description 3");

      // Verify counts
      expect(await factory.totalRegistries()).to.equal(3);
      expect(await factory.getRegistryCountByCreator(addr1.address)).to.equal(
        2
      );
      expect(await factory.getRegistryCountByCreator(addr2.address)).to.equal(
        1
      );

      // Verify all registries are tracked
      const allRegistries = await factory.getAllRegistries();
      expect(allRegistries.length).to.equal(3);
    });
  });
});
