// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GeneralizedClaimRegistry {
    // =======================
    // Structs
    // =======================
    struct Method {
        uint16 methodId; // e.g., 1 = SHA-256
        string name; // "SHA-256"
        string specURI; // optional reference
        uint32 fpSizeBytes; // size of fingerprint
        bool active;
    }

    struct ExternalID {
        uint16 extId; // e.g., 1 = RSA-2048, 2 = ECDSA, 3 = HMAC
        string specURI; // spec or doc link
        uint32 sigSizeHint; // expected signature/MAC size (0 = variable)
        bool active;
    }

    struct Claim {
        address creator;
        string metadata;
        bytes fingerprint;
        uint64 timestamp;
        uint16 methodId;
        uint16 externalId;
        bytes externalSig; // signature == XID like HMAC
        bytes pubKey; // public key (or empty for HMAC)
        string extURI; // optional external reference for univerisity repo URL
    }

    // =======================
    // Storage
    // =======================
    address public admin;
    bool public adminLocked = false;

    mapping(uint16 => Method) public methods;
    mapping(uint16 => ExternalID) public externalIDs;
    mapping(uint16 => mapping(bytes32 => Claim)) public claimsById;

    // =======================
    // Events
    // =======================
    event MethodRegistered(
        uint16 indexed methodId,
        string name,
        uint32 fpSizeBytes
    );
    event MethodActiveSet(uint16 indexed methodId, bool active);
    event ExternalIDRegistered(
        uint16 indexed extId,
        string specURI,
        uint32 sigSizeHint
    );
    event ExternalIDActiveSet(uint16 indexed extId, bool active);
    event Claimed(
        uint16 indexed methodId,
        bytes fingerprint,
        uint16 externalId,
        bytes32 indexed digest,
        address indexed creator
    );
    event AdminLocked();

    // =======================
    // Constructor
    // =======================
    constructor() {
        admin = msg.sender;
    }

    // =======================
    // Admin functions
    // =======================
    function lockAdmin() external {
        require(msg.sender == admin, "auth");
        adminLocked = true;
        emit AdminLocked();
    }

    function transferAdmin(address newAdmin) external {
        require(msg.sender == admin && !adminLocked, "auth");
        require(newAdmin != address(0), "invalid admin");
        admin = newAdmin;
    }

    function registerMethod(
        uint16 methodId,
        string calldata name,
        string calldata specURI,
        uint32 fpSizeBytes
    ) external {
        require(msg.sender == admin && !adminLocked, "auth");
        require(methods[methodId].fpSizeBytes == 0, "exists");
        methods[methodId] = Method(methodId, name, specURI, fpSizeBytes, true);
        emit MethodRegistered(methodId, name, fpSizeBytes);
    }

    function setMethodActive(uint16 methodId, bool active) external {
        require(msg.sender == admin && !adminLocked, "auth");
        methods[methodId].active = active;
        emit MethodActiveSet(methodId, active);
    }

    function registerExternalID(
        uint16 extId,
        string calldata specURI,
        uint32 sigSizeHint
    ) external {
        require(msg.sender == admin && !adminLocked, "auth");
        require(externalIDs[extId].extId == 0, "exists");
        externalIDs[extId] = ExternalID(extId, specURI, sigSizeHint, true);
        emit ExternalIDRegistered(extId, specURI, sigSizeHint);
    }

    function setExternalIDActive(uint16 extId, bool active) external {
        require(msg.sender == admin && !adminLocked, "auth");
        externalIDs[extId].active = active;
        emit ExternalIDActiveSet(extId, active);
    }

    // =======================
    // Claim functions
    // =======================
    function claimByIdwithExternalSig(
        uint16 methodId,
        uint16 externalId,
        bytes calldata fingerprint,
        bytes calldata externalSig,
        bytes calldata pubkey,
        string calldata metadata,
        string calldata extURI
    ) external {
        _validateAndStoreClaim(
            methodId,
            externalId,
            fingerprint,
            externalSig,
            pubkey,
            metadata,
            extURI
        );
    }

    function claimById(
        uint16 methodId,
        uint16 externalId,
        bytes calldata fingerprint,
        string calldata metadata,
        string calldata extURI
    ) external {
        _validateAndStoreClaim(
            methodId,
            externalId,
            fingerprint,
            bytes(""),
            bytes(""),
            metadata,
            extURI
        );
    }

    // =======================
    // Internal helper
    // =======================
    function _validateAndStoreClaim(
        uint16 methodId,
        uint16 externalId,
        bytes calldata fingerprint,
        bytes memory externalSig,
        bytes memory pubkey,
        string calldata metadata,
        string calldata extURI
    ) internal {
        Method memory m = methods[methodId];
        require(m.active, "method inactive");

        ExternalID memory ext = externalIDs[externalId];
        require(ext.active, "externalID inactive");

        if (ext.sigSizeHint != 0) {
            require(externalSig.length <= ext.sigSizeHint, "sig too large");
        }

        bytes32 digest = keccak256(
            abi.encodePacked(fingerprint, m.methodId, ext.extId)
        );
        Claim storage c = claimsById[methodId][digest];
        require(c.creator == address(0), "claim exists");

        c.creator = msg.sender;
        c.metadata = metadata;
        c.fingerprint = fingerprint;

        c.timestamp = uint64(block.timestamp);
        c.methodId = methodId;
        c.externalId = externalId;
        c.externalSig = externalSig;
        c.pubKey = pubkey;
        c.extURI = extURI;

        emit Claimed(methodId, fingerprint, ext.extId, digest, msg.sender);
    }

    // =======================
    // View functions
    // =======================
    function getClaimById(
        uint16 methodId,
        bytes calldata fingerprint
    ) external view returns (Claim memory) {
        uint16 extId = 0;
        bytes32 digest = keccak256(
            abi.encodePacked(fingerprint, methodId, extId)
        );
        return claimsById[methodId][digest];
    }

    function getClaimByIdWithExtId(
        uint16 methodId,
        bytes calldata fingerprint,
        uint16 extId
    ) external view returns (Claim memory) {
        bytes32 digest = keccak256(
            abi.encodePacked(fingerprint, methodId, extId)
        );
        return claimsById[methodId][digest];
    }

    function getMetadataById(
        uint16 methodId,
        bytes calldata fingerprint,
        uint16 sigId
    ) external view returns (string memory) {
        bytes32 digest = keccak256(
            abi.encodePacked(fingerprint, methodId, sigId)
        );
        return claimsById[methodId][digest].metadata;
    }
}
