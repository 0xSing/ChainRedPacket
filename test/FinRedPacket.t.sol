// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/FinRedPacket.sol";
import "./test_contracts/FinTestToken.sol";

contract FinRedPacketTest is Test {
    FinRedPacket public redPacket;
    FinTestToken public erc20;

    address public bob = 0xEC387c860077bE28E2665eB40Ff5597F5F159950;
    address public alice = address(2);
    address public jack = address(3);
    address public a = address(4);
    address public b = address(5);
    address public c = address(6);
    address public d = address(7);

    function setUp() public {
        redPacket = new FinRedPacket(0x16178b55b663Fa065f8054391C15cDa30B700Add);
        erc20 = new FinTestToken(0);

        erc20.mint(bob, 1000000000000000);

        vm.prank(bob);
        erc20.approve(address(redPacket), 1000000000000000);

        vm.deal(bob, 1000 ether);
    }

    function testCreate20() public {
        vm.prank(bob);
        uint256 id = redPacket.createRedPacket(4, true, 1686050002, "test", "test packet", 1, address(erc20), 1000000000000000);

        (
            address tokenAddress,
            uint256 remainingTokens,
            uint256 totalNumber,
            uint256 claimedNumber,
            uint256 ifrandom,
            bool expired,
            uint256 claimedAmount
        )
        = redPacket.checkAvailability(id);

        assertEq(tokenAddress, address(erc20));
        assertEq(remainingTokens, 1000000000000000);
        assertEq(totalNumber, 4);
        assertEq(claimedNumber, 0);
        assertEq(ifrandom, 1);
        assertEq(expired, false);
        assertEq(claimedAmount, 0);
        
    }

    function testCreate20Expired() public {
        vm.prank(bob);
        uint256 id = redPacket.createRedPacket(4, true, 1686050002, "test", "test packet", 1, address(erc20), 1000000000000000);
        
        vm.warp(1686050004);
        console.log(block.timestamp);

        (
            address tokenAddress,
            uint256 remainingTokens,
            uint256 totalNumber,
            uint256 claimedNumber,
            uint256 ifrandom,
            bool expired,
            uint256 claimedAmount
        )
        = redPacket.checkAvailability(id);

        assertEq(tokenAddress, address(erc20));
        assertEq(remainingTokens, 1000000000000000);
        assertEq(totalNumber, 4);
        assertEq(claimedNumber, 0);
        assertEq(ifrandom, 1);
        assertEq(expired, true);
        assertEq(claimedAmount, 0);
    }

    
    function testCreateEther() public {
        vm.prank(bob);
        uint256 id = redPacket.createRedPacket{value: 10000000000000000000}(4, true, 1686050002, "test eth", "test eth packet", 0, address(0), 10000000000000000000);

        (
            address tokenAddress,
            uint256 remainingTokens,
            uint256 totalNumber,
            uint256 claimedNumber,
            uint256 ifrandom,
            bool expired,
            uint256 claimedAmount
        )
        = redPacket.checkAvailability(id);

        assertEq(tokenAddress, address(0));
        assertEq(remainingTokens, 10000000000000000000);
        assertEq(totalNumber, 4);
        assertEq(claimedNumber, 0);
        assertEq(ifrandom, 1);
        assertEq(expired, false);
        assertEq(claimedAmount, 0);
    }

    function testCreateEtherExpired() public {
        vm.prank(bob);
        uint256 id = redPacket.createRedPacket{value: 10000000000000000000}(4, true, 1686050002, "test eth", "test eth packet", 0, address(0), 10000000000000000000);

        vm.warp(1686050004);
        console.log(block.timestamp);
        
        (
            address tokenAddress,
            uint256 remainingTokens,
            uint256 totalNumber,
            uint256 claimedNumber,
            uint256 ifrandom,
            bool expired,
            uint256 claimedAmount
        )
        = redPacket.checkAvailability(id);

        assertEq(tokenAddress, address(0));
        assertEq(remainingTokens, 10000000000000000000);
        assertEq(totalNumber, 4);
        assertEq(claimedNumber, 0);
        assertEq(ifrandom, 1);
        assertEq(expired, true);
        assertEq(claimedAmount, 0);
    }

    function testOwnerClaimExpired() public {
        vm.startPrank(bob);
        uint256 id1 = redPacket.createRedPacket{value: 10000000000000000000}(4, true, 1, "test eth", "test eth packet", 0, address(0), 10000000000000000000);
        redPacket.createRedPacket{value: 10 ether}(4, true, 2, "test eth", "test eth packet", 0, address(0), 10000000000000000000);
        redPacket.createRedPacket(4, true, 3, "test 20", "test 20 packet", 1, address(erc20), 1000000000000000);

        vm.warp(1686050004);
        console.log(block.timestamp);

        vm.stopPrank();

        uint256 preEth = address(this).balance;
        redPacket.ownerRefund(id1);

        assertEq(address(this).balance, preEth + 10000000000000000000);

        redPacket.getExpiredPackets(0, redPacket.getRedPacketNum());

        uint256 preEth2 = address(this).balance;
        uint256 pre20  = erc20.balanceOf(address(this));
        redPacket.ownerRefundRange(0, redPacket.getRedPacketNum());

        assertEq(address(this).balance, preEth2 + 10000000000000000000);
        assertEq(erc20.balanceOf(address(this)), pre20 + 1000000000000000);

        
    }

    receive() external payable {
    }

    
    


}