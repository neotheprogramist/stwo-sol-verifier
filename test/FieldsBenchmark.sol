// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../contracts/fields/M31Field.sol";
import "../contracts/fields/CM31Field.sol";
import "../contracts/fields/QM31Field.sol";

contract FieldsBenchmark is Test {
    function testM31Gas() public {
        console.log("=== M31 GAS TESTS ===");

        uint32 a = 1234567;
        uint32 b = 7654321;

        uint256 gasStart = gasleft();
        uint32 result = M31Field.add(a, b);
        uint256 gasUsed = gasStart - gasleft();
        console.log("M31 add gas:", gasUsed);
        console.log("M31 add result:", result);

        gasStart = gasleft();
        result = M31Field.mul(a, b);
        gasUsed = gasStart - gasleft();
        console.log("M31 mul gas:", gasUsed);
        console.log("M31 mul result:", result);

        gasStart = gasleft();
        result = M31Field.square(a);
        gasUsed = gasStart - gasleft();
        console.log("M31 square gas:", gasUsed);
        console.log("M31 square result:", result);

        gasStart = gasleft();
        result = M31Field.inverse(a);
        gasUsed = gasStart - gasleft();
        console.log("M31 inverse gas:", gasUsed);
        console.log("M31 inverse result:", result);
    }

    function testCM31Gas() public {
        console.log("=== CM31 GAS TESTS ===");

        CM31Field.CM31 memory a = CM31Field.fromM31(1234567, 7654321);
        CM31Field.CM31 memory b = CM31Field.fromM31(9876543, 3456789);

        uint256 gasStart = gasleft();
        CM31Field.CM31 memory result = CM31Field.add(a, b);
        uint256 gasUsed = gasStart - gasleft();
        console.log("CM31 add gas:", gasUsed);
        console.log("CM31 add result:", result.real, result.imag);

        gasStart = gasleft();
        result = CM31Field.mul(a, b);
        gasUsed = gasStart - gasleft();
        console.log("CM31 mul gas:", gasUsed);
        console.log("CM31 mul result:", result.real, result.imag);

        gasStart = gasleft();
        result = CM31Field.square(a);
        gasUsed = gasStart - gasleft();
        console.log("CM31 square gas:", gasUsed);
        console.log("CM31 square result:", result.real, result.imag);

        gasStart = gasleft();
        result = CM31Field.inverse(a);
        gasUsed = gasStart - gasleft();
        console.log("CM31 inverse gas:", gasUsed);
        console.log("CM31 inverse result:", result.real, result.imag);
    }

    function testQM31Gas() public {
        console.log("=== QM31 GAS TESTS ===");

        QM31Field.QM31 memory a = QM31Field.fromM31(
            1234567,
            7654321,
            2468135,
            8642097
        );
        QM31Field.QM31 memory b = QM31Field.fromM31(
            9876543,
            3456789,
            1357924,
            6420864
        );

        uint256 gasStart = gasleft();
        QM31Field.QM31 memory result = QM31Field.add(a, b);
        uint256 gasUsed = gasStart - gasleft();
        console.log("QM31 add gas:", gasUsed);
        console.log("QM31 add result:", result.first.real, result.first.imag);

        gasStart = gasleft();
        result = QM31Field.mul(a, b);
        gasUsed = gasStart - gasleft();
        console.log("QM31 mul gas:", gasUsed);
        console.log("QM31 mul result:", result.first.real, result.first.imag);

        gasStart = gasleft();
        result = QM31Field.square(a);
        gasUsed = gasStart - gasleft();
        console.log("QM31 square gas:", gasUsed);
        console.log(
            "QM31 square result:",
            result.first.real,
            result.first.imag
        );

        gasStart = gasleft();
        result = QM31Field.inverse(a);
        gasUsed = gasStart - gasleft();
        console.log("QM31 inverse gas:", gasUsed);
        console.log(
            "QM31 inverse result:",
            result.first.real,
            result.first.imag
        );
    }
}
