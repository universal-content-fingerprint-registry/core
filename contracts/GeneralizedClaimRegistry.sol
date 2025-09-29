// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GeneralizedClaimRegistry {
    struct Method {
        uint16 methodId;
        string name;
        string specURI;
        uint32 fpSizeBytes;
        bool active;
    }

    struct ExternalID {
        uint16 extId;
        string specURI;
        uint32 sigSizeHint;
        bool active;
    }

    struct Claim {
        address creator;
        string metadata;
        bytes fingerprint;
        uint64 timestamp;
        uint16 methodId;
        uint16 externalId;
        bytes externalSig;
        bytes pubKey;
        string extURI;
    }

    struct ClaimParams {
        uint16 methodId;
        uint16 externalId;
        bytes fingerprint;
        bytes externalSig;
        bytes pubKey;
        string metadata;
        string extURI;
    }

    address public admin;
    bool public adminLocked = false;

    mapping(uint16 => Method) public methods;
    mapping(uint16 => ExternalID) public externalIDs;
    mapping(uint16 => mapping(bytes32 => Claim)) public claimsById;

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

    constructor() {
        admin = msg.sender;
    }

    // --- Admin ---
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
        require(methodId != 0, "invalid id");
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
        require(extId != 0, "invalid id");
        require(externalIDs[extId].extId == 0, "exists");
        externalIDs[extId] = ExternalID(extId, specURI, sigSizeHint, true);
        emit ExternalIDRegistered(extId, specURI, sigSizeHint);
    }

    function setExternalIDActive(uint16 extId, bool active) external {
        require(msg.sender == admin && !adminLocked, "auth");
        externalIDs[extId].active = active;
        emit ExternalIDActiveSet(extId, active);
    }

    function claim(ClaimParams calldata p) external {
        _validateAndStoreClaim(p);
    }

    function _validateAndStoreClaim(ClaimParams calldata p) internal {
        Method storage m = methods[p.methodId];
        require(m.active, "method inactive");

        ExternalID storage x = externalIDs[p.externalId];
        require(x.active, "externalID inactive");
        if (x.sigSizeHint != 0) {
            require(p.externalSig.length <= x.sigSizeHint, "sig too large");
        }

        bytes32 digest = keccak256(
            abi.encode(p.fingerprint, p.methodId, p.externalId)
        );

        Claim storage c = claimsById[p.methodId][digest];
        require(c.creator == address(0), "claim exists");

        c.creator = msg.sender;
        c.metadata = p.metadata;
        c.fingerprint = p.fingerprint;
        c.timestamp = uint64(block.timestamp);
        c.methodId = p.methodId;
        c.externalId = p.externalId;
        c.externalSig = p.externalSig;
        c.pubKey = p.pubKey;
        c.extURI = p.extURI;

        emit Claimed(
            p.methodId,
            p.fingerprint,
            p.externalId,
            digest,
            msg.sender
        );
    }

    function getClaimById(
        uint16 methodId,
        bytes calldata fingerprint
    ) external view returns (Claim memory) {
        uint16 extId = 0;
        bytes32 digest = keccak256(abi.encode(fingerprint, methodId, extId));
        return claimsById[methodId][digest];
    }

    function getClaimByIdWithExtId(
        uint16 methodId,
        bytes calldata fingerprint,
        uint16 extId
    ) external view returns (Claim memory) {
        bytes32 digest = keccak256(abi.encode(fingerprint, methodId, extId));
        return claimsById[methodId][digest];
    }

    function getMetadataById(
        uint16 methodId,
        bytes calldata fingerprint,
        uint16 sigId
    ) external view returns (string memory) {
        bytes32 digest = keccak256(abi.encode(fingerprint, methodId, sigId));
        return claimsById[methodId][digest].metadata;
    }
}
