// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./verifier.sol";

contract MessageRelayWithZkpAndSignature is Verifier {
    using Pairing for *;

    address public immutable alpha;
    address public immutable groundStationB;

    mapping(address => bool) public isBeta;
    address[] public betas;

    mapping(uint256 => address) public byRawHash;
    mapping(uint256 => address) public byZkpHash;
    mapping(uint256 => uint256) public escrow;
    mapping(address => uint256) public balances;

    
    uint256 public constant FIELD_PRIME =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    
    event RawRegistered(uint256 indexed rawHashFull, address indexed beta, uint256 escrowed);
    event ZkpAndSigRelay(
        uint256 indexed rawHashFull,
        uint256 indexed zkpHash,
        address indexed beta,
        uint256 amount
    );
    event Withdrawal(address indexed beta, uint256 amount);

    constructor(address _groundStationB, address[] memory _betas) {
        alpha = msg.sender;
        groundStationB = _groundStationB;
        for (uint256 i = 0; i < _betas.length; i++) {
            address b = _betas[i];
            require(b != address(0) && !isBeta[b], "Beta is invalid");
            isBeta[b] = true;
            betas.push(b);
        }
    }


    function registerRawHash(uint256 rawHash, address beta) external payable {
        require(msg.sender == alpha, "Only Alpha can call this function");
        require(isBeta[beta], "Beta address is not whitelisted");
        require(byRawHash[rawHash] == address(0), "rawHashFull already registered");
        require(msg.value > 0, "Must deposit a positive amount");
        byRawHash[rawHash] = beta;
        escrow[rawHash] = msg.value;
        emit RawRegistered(rawHash, beta, msg.value);
    }


    
    function proveAndRelease(
        uint256 rawHash,
        uint256 zkpHash,
        uint256 blocktimestamp,
        uint256 delta,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address beta = msg.sender;
        require(isBeta[beta], "Beta is not authorized");
        require(byRawHash[rawHash] == beta, "Invalid Beta for specified rawHash");
        require(byZkpHash[zkpHash] == address(0), "zkpHash already used");
        byZkpHash[zkpHash] = beta;
        require(
            verifyTx(
                Proof({
                    a: Pairing.G1Point(a[0], a[1]),
                    b: Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]),
                    c: Pairing.G1Point(c[0], c[1])
                }),
                [rawHash % FIELD_PRIME, zkpHash, blocktimestamp, delta ]
            ),
            "invalid proof"
        );
        
        bytes32 aggHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", bytes32(rawHash))
        );
        require(ecrecover(aggHash, v, r, s) == groundStationB, "Invalid signature from groundStationB");
        uint256 amount = escrow[rawHash];
        require(amount > 0, "No escrowed amount available");
        escrow[rawHash] = 0;
        balances[beta] += amount;

        emit ZkpAndSigRelay(rawHash, zkpHash, beta, amount);
    }

    
    function withdraw() external {
        address beta = msg.sender;
        uint256 amount = balances[beta];
        require(amount > 0, "No balance available");

        balances[beta] = 0;

        (bool success, ) = payable(beta).call{value: amount}("");
        require(success, "Withdrawal failed");

        emit Withdrawal(beta, amount);
    }

   
    receive() external payable {}
}
