// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract FinRedPacket is Ownable{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    struct RedPacket {
        Packed packed;
        mapping(address => uint256) claimedList;
        address publicKey;
        address creator;
    }

    struct Packed {
        uint256 packed1; // 0 (128) total_tokens (96) expire_time(32)
        uint256 packed2; // 0 (64) token_addr (160) claimed_numbers(15) total_numbers(15) token_type(1) ifrandom(1)
    }

    struct ExpiredPacket {
        uint256 id;
        address tokenAddr;
        uint256 amount;
        uint256 tokenType;
    }

    event CreationSuccess(
        uint256 total,
        uint256 id,
        string name,
        string message,
        address creator,
        uint256 creationTime,
        address tokenAddress,
        uint256 number,
        bool ifrandom,
        uint256 duration
    );

    event ClaimSuccess(
        uint256 id, 
        address claimer, 
        uint256 claimedValue, 
        address tokenAddress
    );

    event RefundSuccess(
        uint256 id, 
        address tokenAddress, 
        uint256 remainingBalance
    );

    
    uint32 _nonce;
    uint256[] private _redPacketIds;
    mapping(uint256 => bool) private _isAllClaims;
    mapping(uint256 => RedPacket) public redpacketById;
    bytes32 private _seed;
    address private _publicKey;
    address public usdtAddr = 0xa614f803B6FD780986A42c78Ec9c7f77e6DeD13C;

    constructor(address newPublicKey) {
        _publicKey = newPublicKey;
        _seed = keccak256(abi.encodePacked("FinToken Red Packet", block.timestamp, msg.sender));
    }

    function setPublicKey(address newPublicKey) external onlyOwner {
        _publicKey = newPublicKey;
    }

    // Inits a red packet instance
    // tokenType: 0 - ETH  1 - ERC20
    function createRedPacket(
        uint256 number,
        bool ifrandom,
        uint256 duration,
        string memory _message,
        string memory _name,
        uint256 tokenType,
        address tokenAddr,
        uint256 totalTokens
    ) public payable returns (uint256 id) {
        _nonce++;
        require(totalTokens >= number, "#tokens > #packets");
        require(number > 0, "At least 1 recipient");
        require(number <= 1000, "At most 1000 recipients");
        require(tokenType == 0 || tokenType == 1, "Unrecognizable token type");

        uint256 receivedAmount = totalTokens;
        if (tokenType == 0) {
            require(msg.value == totalTokens, "Wrong ETH");
        }
        else if (tokenType == 1) {
            // `received_amount` is not necessarily equal to `_total_tokens`
            uint256 balanceBeforeTransfer = IERC20Upgradeable(tokenAddr).balanceOf(address(this));
            IERC20Upgradeable(tokenAddr).safeTransferFrom(msg.sender, address(this), totalTokens);
            uint256 balanceAfterTransfer = IERC20Upgradeable(tokenAddr).balanceOf(address(this));
            receivedAmount = balanceAfterTransfer - balanceBeforeTransfer;
            require(receivedAmount >= number, "#received > #packets");
        }

        id = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, _nonce,  _seed)));
        {
            uint256 randomType = ifrandom ? 1 : 0;
            RedPacket storage redp = redpacketById[id];
            redp.packed.packed1 = _wrap1(receivedAmount, duration);
            redp.packed.packed2 = _wrap2(tokenAddr, number, tokenType, randomType);
            redp.publicKey = _publicKey;
            redp.creator = msg.sender;
        }
        {
            // as a workaround for "CompilerError: Stack too deep, try removing local variables"
            uint256 number_ = number;
            bool ifrandom_ = ifrandom;
            uint256 duration_ = duration;
            _redPacketIds.push(id);
            emit CreationSuccess(
                receivedAmount,
                id,
                _name,
                _message,
                msg.sender,
                block.timestamp,
                tokenAddr,
                number_,
                ifrandom_,
                duration_
            );
        }
    }

    // It takes the signed msg.sender message as verification passcode
    function claim(
        uint256 id,
        uint256 receivedAmount,
        bytes memory signedMsg
    ) public returns (uint256 claimed) {
        RedPacket storage rp = redpacketById[id];
        Packed memory packed = rp.packed;
        // Unsuccessful
        require(_unbox(packed.packed1, 224, 32) > block.timestamp, "Expired");
        uint256 totalNumber = _unbox(packed.packed2, 239, 15);
        uint256 claimedNumber = _unbox(packed.packed2, 224, 15);
        require(claimedNumber < totalNumber, "Out of stock");

        address publicKey = rp.publicKey;
        require(_verify(signedMsg, publicKey, id, receivedAmount, msg.sender), "Verification failed");

        uint256 claimedTokens = receivedAmount;
        uint256 tokenType = _unbox(packed.packed2, 254, 1);
        uint256 remainingTokens = _unbox(packed.packed1, 128, 96);
        require(claimedTokens <= remainingTokens, "Out of maining, please reobtain the signature");
        if (remainingTokens - claimedTokens == 0) _isAllClaims[id] = true;
        rp.packed.packed1 = _rewriteBox(packed.packed1, 128, 96, remainingTokens - claimedTokens);

        // Penalize greedy attackers by placing duplication check at the very last
        require(rp.claimedList[msg.sender] == 0, "Already claimed");

        rp.claimedList[msg.sender] = claimedTokens;
        rp.packed.packed2 = _rewriteBox(packed.packed2, 224, 15, claimedNumber + 1);

        // Transfer the red packet after state changing
        if (tokenType == 0) payable(msg.sender).transfer(claimedTokens);
        else if (tokenType == 1)
            _safeTransfer(address(uint160(_unbox(packed.packed2, 64, 160))), msg.sender, claimedTokens);
        // Claim success event
        emit ClaimSuccess(id, msg.sender, claimedTokens, address(uint160(_unbox(packed.packed2, 64, 160))));
        return claimedTokens;
    }

    // as a workaround for "CompilerError: Stack too deep, try removing local variables"
    function _verify(
        bytes memory signedMsg, 
        address publicKey,
        uint256 id,
        uint256 amount,
        address recipient
    ) private pure returns (bool verified) {
        bytes memory prefix = "\x19FinToken RedPacket Signed Message:\n32";
        bytes32 prefixedHash = keccak256(abi.encodePacked(prefix, id, amount, recipient));
        address calculatedPublicKey = ECDSA.recover(prefixedHash, signedMsg);
        return (calculatedPublicKey == publicKey);
    }

    // Returns 1. remaining value 2. total number of red packets 3. claimed number of red packets
    function checkAvailability(uint256 id)
        external
        view
        returns (
            address tokenAddress,
            uint256 remainingTokens,
            uint256 totalNumber,
            uint256 claimedNumber,
            uint256 ifrandom,
            bool expired,
            uint256 claimedAmount
        )
    {
        RedPacket storage rp = redpacketById[id];
        Packed memory packed = rp.packed;
        return (
            address(uint160(_unbox(packed.packed2, 64, 160))),
            _unbox(packed.packed1, 128, 96),
            _unbox(packed.packed2, 239, 15),
            _unbox(packed.packed2, 224, 15),
            _unbox(packed.packed2, 255, 1),
            block.timestamp > _unbox(packed.packed1, 224, 32),
            rp.claimedList[msg.sender]
        );
    }

    // Get red packets that have expired
    function getExpiredPackets(uint256 startIndex, uint256 endIndex) public view returns (ExpiredPacket[] memory, uint256 validIndex) {
        require(startIndex < endIndex, "Invalid range");
        require(endIndex <= _redPacketIds.length, "End index out of range");

        ExpiredPacket[] memory chunk = new ExpiredPacket[](endIndex - startIndex);
        uint256 offset = 0;
        for (uint256 i = startIndex; i < endIndex; i++) {
            uint256 id = _redPacketIds[i];
            RedPacket storage redPacket = redpacketById[id];

            if ( !_isAllClaims[id] && 
                block.timestamp > _unbox(redPacket.packed.packed1, 224, 32)) {
                
                chunk[offset] = ExpiredPacket({
                    id: id,
                    tokenAddr: address(uint160(_unbox(redPacket.packed.packed2, 64, 160))),
                    amount: _unbox(redPacket.packed.packed1, 128, 96),
                    tokenType: _unbox(redPacket.packed.packed2, 254, 1)
                });
                
                offset++;
            }
            
        }
        return (chunk, offset);
    }

    function ownerRefundRange(uint256 startIndex, uint256 endIndex) external onlyOwner {
        (ExpiredPacket[] memory expiredPackets, uint256  validIndex)= getExpiredPackets(startIndex, endIndex);

        for (uint256 i = 0; i < validIndex; i++){
            ExpiredPacket memory redPacket = expiredPackets[i];

            if (redPacket.tokenType == 0) {
                payable(owner()).transfer(redPacket.amount);
            } else if (redPacket.tokenType == 1) {
                _transferToken(redPacket.tokenAddr, owner(), redPacket.amount);
            }

            _isAllClaims[redPacket.id] = true;
            emit RefundSuccess(redPacket.id, redPacket.tokenAddr, redPacket.amount);
        }
    }

    function ownerRefund(uint256 id) external onlyOwner {
        RedPacket storage rp = redpacketById[id];
        Packed memory packed = rp.packed;

        require(_unbox(packed.packed1, 224, 32) < block.timestamp, "not Expired");
        require(!_isAllClaims[id], "has no value");

        uint256 tokenType = _unbox(packed.packed2, 254, 1);
        uint256 remainingTokens = _unbox(packed.packed1, 128, 96);
        address tokenAddr = address(uint160(_unbox(packed.packed2, 64, 160)));

        _isAllClaims[id] = true;

        if (tokenType == 0) {
            payable(owner()).transfer(remainingTokens);
        } else if (tokenType == 1) {
            _transferToken(tokenAddr, owner(), remainingTokens);
        }


        emit RefundSuccess(id, tokenAddr, remainingTokens);
    }

    function getRedPacketNum() external view returns(uint256){
        return _redPacketIds.length;
    }

    //------------------------------------------------------------------
    /**
     * position      position in a memory block
     * size          data size
     * data          data
     * box() inserts the data in a 256bit word with the given position and returns it
     * data is checked by validRange() to make sure it is not over size
     **/

    function _box(
        uint16 position,
        uint16 size,
        uint256 data
    ) internal pure returns (uint256 boxed) {
        require(_validRange(size, data), "Value out of range BOX");
        assembly {
            // data << position
            boxed := shl(position, data)
        }
    }

    /**
     * position      position in a memory block
     * size          data size
     * base          base data
     * unbox() extracts the data out of a 256bit word with the given position and returns it
     * base is checked by validRange() to make sure it is not over size
     **/

    function _unbox(
        uint256 base,
        uint16 position,
        uint16 size
    ) internal pure returns (uint256 unboxed) {
        require(_validRange(256, base), "Value out of range UNBOX");
        assembly {
            // (((1 << size) - 1) & base >> position)
            unboxed := and(sub(shl(size, 1), 1), shr(position, base))
        }
    }

    /**
     * size          data size
     * data          data
     * validRange()  checks if the given data is over the specified data size
     **/

    function _validRange(uint16 size, uint256 data) internal pure returns (bool ifValid) {
        assembly {
            // 2^size > data or size ==256
            ifValid := or(eq(size, 256), gt(shl(size, 1), data))
        }
    }

    /**
     * _box          32byte data to be modified
     * position      position in a memory block
     * size          data size
     * data          data to be inserted
     * rewriteBox() updates a 32byte word with a data at the given position with the specified size
     **/

    function _rewriteBox(
        uint256 box_,
        uint16 position,
        uint16 size,
        uint256 data
    ) internal pure returns (uint256 boxed) {
        assembly {
            // mask = ~((1 << size - 1) << position)
            // _box = (mask & _box) | ()data << position)
            boxed := or(and(box_, not(shl(position, sub(shl(size, 1), 1)))), shl(position, data))
        }
    }

    function _transferToken(
        address tokenAddress,
        address recipientAddress,
        uint256 amount
    ) internal {
        IERC20Upgradeable(tokenAddress).safeTransfer(recipientAddress, amount);
    }

    // A boring wrapper
    function _random(bytes32 seed_, uint32 nonceRand) internal view returns (uint256 rand) {
        return uint256(keccak256(abi.encodePacked(nonceRand, msg.sender, seed_, block.timestamp))) + 1;
    }

    function _wrap1(uint256 _totalTokens, uint256 _duration) internal view returns (uint256 packed1) {
        uint256 _packed1 = 0;
        _packed1 |= _box(128, 96, _totalTokens); // total tokens = 80 bits = ~8 * 10^10 18 decimals
        _packed1 |= _box(224, 32, (block.timestamp + _duration)); // expiration_time = 32 bits (until 2106)
        return _packed1;
    }

    function _wrap2(
        address _tokenAddr,
        uint256 _number,
        uint256 _tokenType,
        uint256 _ifrandom
    ) internal pure returns (uint256 packed2) {
        uint256 _packed2 = 0;
        _packed2 |= _box(64, 160, uint160(_tokenAddr)); // token_address = 160 bits
        _packed2 |= _box(224, 15, 0); // claimed_number = 14 bits 16384
        _packed2 |= _box(239, 15, _number); // total_number = 14 bits 16384
        _packed2 |= _box(254, 1, _tokenType); // token_type = 1 bit 2
        _packed2 |= _box(255, 1, _ifrandom); // ifrandom = 1 bit 2
        return _packed2;
    }

    function _safeTransfer(address token, address to, uint value) internal returns (bool){
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        if (token == usdtAddr) {
            return success;
        }
        return (success && (data.length == 0 || abi.decode(data, (bool))));
    }
}
