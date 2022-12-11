pragma experimental SMTChecker;
pragma experimental "ABIEncoderV2";

contract C {
  struct S { uint x; uint[] b; }
  function f() public pure returns (S memory, bytes memory, uint[][2] memory) {
    return abi.decode("abc", (S, bytes, uint[][2]));
  }
}
// ----
// Warning: (32-67): Experimental features are turned on. Do not use experimental features on live deployments.
// Warning: (151-159): Assertion checker does not yet support the type of this variable.
// Warning: (206-209): Assertion checker does not yet implement type abi
// Warning: (225-226): Assertion checker does not yet implement type type(struct C.S storage pointer)
// Warning: (235-241): Assertion checker does not yet implement type type(uint256[] memory)
// Warning: (235-244): Assertion checker does not yet implement type type(uint256[] memory[2] memory)
// Warning: (206-246): Assertion checker does not yet implement this type of function call.
