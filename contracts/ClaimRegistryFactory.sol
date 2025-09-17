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
        address registryAddress;
        address creator;
        uint256 createdAt;
        string name;
        string description;
        bool active;
    }

    // =======================
    // Storage
    // =======================
    address public owner;
    uint256 public totalRegistries;

    // Mapping from registry address to registry info
    mapping(address => RegistryInfo) public registries;

    // Mapping from registry ID to registry address
    mapping(uint256 => address) public registryById;

    // Array of all registry addresses
    address[] public allRegistries;

    // Mapping from creator to their registries
    mapping(address => address[]) public registriesByCreator;

    // =======================
    // Modifiers
    // =======================
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    modifier onlyRegistryOwner(address registryAddress) {
        require(
            registries[registryAddress].creator == msg.sender,
            "Only registry creator can call this function"
        );
        _;
    }

    modifier registryExists(address registryAddress) {
        require(
            registries[registryAddress].registryAddress != address(0),
            "Registry does not exist"
        );
        _;
    }

    // =======================
    // Constructor
    // =======================
    constructor() {
        owner = msg.sender;
    }

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
            registryAddress: registryAddress,
            creator: msg.sender,
            createdAt: block.timestamp,
            name: name,
            description: description,
            active: true
        });

        // Store registry info
        registries[registryAddress] = info;
        registryById[totalRegistries] = registryAddress;
        allRegistries.push(registryAddress);
        registriesByCreator[msg.sender].push(registryAddress);

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

    /**
     * @dev Create multiple registries in a single transaction
     * @param names Array of names for the registries
     * @param descriptions Array of descriptions for the registries
     * @return registryAddresses Array of addresses of the newly created registries
     */
    function createMultipleRegistries(
        string[] calldata names,
        string[] calldata descriptions
    ) external returns (address[] memory registryAddresses) {
        require(names.length == descriptions.length, "Arrays length mismatch");
        require(names.length > 0, "Empty arrays");
        require(names.length <= 10, "Too many registries in one transaction");

        registryAddresses = new address[](names.length);

        for (uint256 i = 0; i < names.length; i++) {
            registryAddresses[i] = _createRegistry(names[i], descriptions[i]);
        }

        return registryAddresses;
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
     * @dev Get all registries created by a specific address
     * @param creator Address of the creator
     * @return creatorRegistries Array of registry addresses created by the creator
     */
    function getRegistriesByCreator(
        address creator
    ) external view returns (address[] memory creatorRegistries) {
        return registriesByCreator[creator];
    }

    /**
     * @dev Get all registry addresses
     * @return allAddresses Array of all registry addresses
     */
    function getAllRegistries()
        external
        view
        returns (address[] memory allAddresses)
    {
        return allRegistries;
    }

    /**
     * @dev Get the number of registries created by a specific address
     * @param creator Address of the creator
     * @return count Number of registries created by the creator
     */
    function getRegistryCountByCreator(
        address creator
    ) external view returns (uint256 count) {
        return registriesByCreator[creator].length;
    }

    /**
     * @dev Check if a registry exists
     * @param registryAddress Address to check
     * @return exists True if the registry exists
     */
    function doesRegistryExist(
        address registryAddress
    ) external view returns (bool exists) {
        return registries[registryAddress].registryAddress != address(0);
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

    // =======================
    // Admin Functions
    // =======================

    /**
     * @dev Transfer ownership of the factory (only by current owner)
     * @param newOwner Address of the new owner
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
    }

    /**
     * @dev Get factory statistics
     * @return total Total number of registries created
     * @return factoryOwner Address of the factory owner
     */
    function getFactoryStats()
        external
        view
        returns (uint256 total, address factoryOwner)
    {
        return (totalRegistries, owner);
    }
}
