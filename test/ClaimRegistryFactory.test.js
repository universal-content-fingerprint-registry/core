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
    it("Should initialize with zero total registries", async function () {
      expect(await factory.totalRegistries()).to.equal(0);
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

      expect(await factory.totalRegistries()).to.equal(3);

      // Check individual registries by ID
      const registry0 = await factory.getRegistryInfo(
        await factory.registryById(0)
      );
      const registry1 = await factory.getRegistryInfo(
        await factory.registryById(1)
      );
      const registry2 = await factory.getRegistryInfo(
        await factory.registryById(2)
      );

      expect(registry0.creator).to.equal(addr1.address);
      expect(registry1.creator).to.equal(addr1.address);
      expect(registry2.creator).to.equal(addr2.address);
    });

    it("Should maintain registry count correctly", async function () {
      await factory
        .connect(addr1)
        .createRegistry("Registry 1", "Description 1");
      await factory
        .connect(addr2)
        .createRegistry("Registry 2", "Description 2");

      expect(await factory.totalRegistries()).to.equal(2);
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

      expect(info.creator).to.equal(addr1.address);
      expect(info.name).to.equal("Registry 1");
      expect(info.description).to.equal("Description 1");
      expect(info.active).to.equal(true);
    });

    it("Should track registry addresses correctly", async function () {
      expect(await factory.doesRegistryExist(registryAddress1)).to.equal(true);
      expect(await factory.doesRegistryExist(registryAddress2)).to.equal(true);

      const registry1Info = await factory.getRegistryInfo(registryAddress1);
      const registry2Info = await factory.getRegistryInfo(registryAddress2);

      expect(registry1Info.creator).to.equal(addr1.address);
      expect(registry2Info.creator).to.equal(addr2.address);
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

  describe("Factory Stats", function () {
    it("Should return factory stats", async function () {
      await factory.connect(addr1).createRegistry("Test", "Test Description");

      const total = await factory.getFactoryStats();
      expect(total).to.equal(1);
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

      // Verify registries by checking their info
      const registry0Info = await factory.getRegistryInfo(
        await factory.registryById(0)
      );
      const registry1Info = await factory.getRegistryInfo(
        await factory.registryById(1)
      );
      const registry2Info = await factory.getRegistryInfo(
        await factory.registryById(2)
      );

      expect(registry0Info.creator).to.equal(addr1.address);
      expect(registry1Info.creator).to.equal(addr1.address);
      expect(registry2Info.creator).to.equal(addr2.address);
    });
  });
});
