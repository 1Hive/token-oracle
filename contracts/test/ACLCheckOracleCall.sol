pragma solidity ^0.4.24;

import "@aragon/os/contracts/acl/IACLOracle.sol";

contract ACLCheckOracleCall {

    bytes32 private constant ANY_BYTES32 = keccak256("ANY_BYTES32");
    address private constant ANY_ADDRESS = 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF;

    function checkOracle(IACLOracle _oracleAddr, uint256[] _how, uint256 _oracleGasLimit) public view returns (bool canPerform, uint256 gasUsed) {
        bytes4 sig = _oracleAddr.canPerform.selector;

        // a raw call is required so we can return false if the call reverts, rather than reverting
        bytes memory checkCalldata = abi.encodeWithSelector(sig, ANY_ADDRESS, ANY_ADDRESS, ANY_BYTES32, _how);

        bool ok;

        uint256 currentGas = gasleft();

        assembly {
            ok := staticcall(_oracleGasLimit, _oracleAddr, add(checkCalldata, 0x20), mload(checkCalldata), 0, 0)
        }

        gasUsed = currentGas - gasleft();

        if (!ok) {
            return (false, gasUsed);
        }

        uint256 size;
        assembly { size := returndatasize }
        if (size != 32) {
            return (false, gasUsed);
        }

        bool result;
        assembly {
            let ptr := mload(0x40)       // get next free memory ptr
            returndatacopy(ptr, 0, size) // copy return from above `staticcall`
            result := mload(ptr)         // read data at ptr and set it to result
            mstore(ptr, 0)               // set pointer memory to 0 so it still is the next free ptr
        }

        return (result, gasUsed);
    }
}
