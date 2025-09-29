// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GeneralizedClaimRegistry.sol";

/**
 * @title ClaimRegistryFactory
 * @dev Factory contract for creating GeneralizedClaimRegistry instances
 * @notice This contract allows users to deploy new claim registry instances
 */
contract ClaimRegistryFactory {
    // =======================
    // Events
    // =======================
    event RegistryCreated(
        address indexed registryAddress,
        address indexed creator,
        uint256 indexed registryId,
        string name,
        string description
    );

    event RegistryNameUpdated(
        address indexed registryAddress,
        string oldName,
        string newName
    );

    event RegistryDescriptionUpdated(
        address indexed registryAddress,
        string oldDescription,
        string newDescription
    );

    // =======================
    // Structs
    // =======================
    struct RegistryInfo {
        address creator;
        uint256 createdAt;
        string name;
        string description;
        bool active;
    }

    // =======================
    // Storage
    // =======================
    uint256 public totalRegistries;

    // Mapping from registry address to registry info
    mapping(address => RegistryInfo) public registries;

    // Mapping from registry ID to registry address
    mapping(uint256 => address) public registryById;

    // =======================
    // Modifiers
    // =======================
    modifier onlyRegistryOwner(address registryAddress) {
        require(
            registries[registryAddress].creator == msg.sender,
            "Only registry creator can call this function"
        );
        _;
    }

    modifier registryExists(address registryAddress) {
        require(
            registries[registryAddress].creator != address(0),
            "Registry does not exist"
        );
        _;
    }

    // =======================
    // Constructor
    // =======================
    constructor() {}

    // =======================
    // Core Functions
    // =======================

    /**
     * @dev Create a new GeneralizedClaimRegistry instance
     * @param name Human-readable name for the registry
     * @param description Description of the registry's purpose
     * @return registryAddress The address of the newly created registry
     */
    function createRegistry(
        string calldata name,
        string calldata description
    ) external returns (address registryAddress) {
        return _createRegistry(name, description);
    }

    /**
     * @dev Internal function to create a new GeneralizedClaimRegistry instance
     * @param name Human-readable name for the registry
     * @param description Description of the registry's purpose
     * @return registryAddress The address of the newly created registry
     */
    function _createRegistry(
        string calldata name,
        string calldata description
    ) internal returns (address registryAddress) {
        // Deploy new GeneralizedClaimRegistry
        GeneralizedClaimRegistry newRegistry = new GeneralizedClaimRegistry();
        registryAddress = address(newRegistry);

        // Transfer admin rights to the creator
        newRegistry.transferAdmin(msg.sender);

        // Create registry info
        RegistryInfo memory info = RegistryInfo({
            creator: msg.sender,
            createdAt: block.timestamp,
            name: name,
            description: description,
            active: true
        });

        // Store registry info
        registries[registryAddress] = info;
        registryById[totalRegistries] = registryAddress;

        // Increment counter
        totalRegistries++;

        // Emit event
        emit RegistryCreated(
            registryAddress,
            msg.sender,
            totalRegistries - 1,
            name,
            description
        );

        return registryAddress;
    }

    // =======================
    // Registry Management
    // =======================

    /**
     * @dev Update the name of a registry (only by creator)
     * @param registryAddress Address of the registry to update
     * @param newName New name for the registry
     */
    function updateRegistryName(
        address registryAddress,
        string calldata newName
    )
        external
        registryExists(registryAddress)
        onlyRegistryOwner(registryAddress)
    {
        string memory oldName = registries[registryAddress].name;
        registries[registryAddress].name = newName;

        emit RegistryNameUpdated(registryAddress, oldName, newName);
    }

    /**
     * @dev Update the description of a registry (only by creator)
     * @param registryAddress Address of the registry to update
     * @param newDescription New description for the registry
     */
    function updateRegistryDescription(
        address registryAddress,
        string calldata newDescription
    )
        external
        registryExists(registryAddress)
        onlyRegistryOwner(registryAddress)
    {
        string memory oldDescription = registries[registryAddress].description;
        registries[registryAddress].description = newDescription;

        emit RegistryDescriptionUpdated(
            registryAddress,
            oldDescription,
            newDescription
        );
    }

    /**
     * @dev Deactivate a registry (only by creator)
     * @param registryAddress Address of the registry to deactivate
     */
    function deactivateRegistry(
        address registryAddress
    )
        external
        registryExists(registryAddress)
        onlyRegistryOwner(registryAddress)
    {
        registries[registryAddress].active = false;
    }

    /**
     * @dev Reactivate a registry (only by creator)
     * @param registryAddress Address of the registry to reactivate
     */
    function reactivateRegistry(
        address registryAddress
    )
        external
        registryExists(registryAddress)
        onlyRegistryOwner(registryAddress)
    {
        registries[registryAddress].active = true;
    }

    // =======================
    // View Functions
    // =======================

    /**
     * @dev Get information about a specific registry
     * @param registryAddress Address of the registry
     * @return info RegistryInfo struct containing all registry details
     */
    function getRegistryInfo(
        address registryAddress
    )
        external
        view
        registryExists(registryAddress)
        returns (RegistryInfo memory info)
    {
        return registries[registryAddress];
    }

    /**
     * @dev Check if a registry exists
     * @param registryAddress Address to check
     * @return exists True if the registry exists
     */
    function doesRegistryExist(
        address registryAddress
    ) external view returns (bool exists) {
        return registries[registryAddress].creator != address(0);
    }

    /**
     * @dev Get registry address by ID
     * @param registryId ID of the registry
     * @return registryAddress Address of the registry
     */
    function getRegistryById(
        uint256 registryId
    ) external view returns (address registryAddress) {
        require(registryId < totalRegistries, "Registry ID does not exist");
        return registryById[registryId];
    }


    /**
     * @dev Get factory statistics
     * @return total Total number of registries created
     */
    function getFactoryStats()
        external
        view
        returns (uint256 total)
    {
        return (totalRegistries);
    }
}
