pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT

import "hardhat/console.sol";

contract YourContract1 {


    // type casting

    struct Foo {
      uint kind;
      bytes payload;
    }

    struct Bar {
      uint b;
    }

    struct Dak {
      string d;
    }

    // struct ChildB {
    //   uint kind;
    //   uint8[2] values;
    // }

    function typecast() public pure returns (string memory) {
      // I want dynamic types for structs.
      // convert struct to bytes, and then back?
        // custom serialize/deserialize to bytes
        // then define the lookup that can read the enum
        // this is unsafe, i.e. the memory bugs need to be thought of carefully.

      // what if we do wrappers - worked.
      Bar memory bar = Bar(3);
      Dak memory dak = Dak("hello");

      Foo memory barF = Foo(1, abi.encode(bar));
      Foo memory dakF = Foo(2, abi.encode(dak));

      Bar memory barD = abi.decode(barF.payload, (Bar));

      if (bar.b == barD.b) {
        return "success";
      } else {
        return "failed";
      }


      
      // doesn't work: the decode() function hashes the ABI type which is a tuple of the struct components
      // so the types are not convertible.

      // ChildA memory valA = ChildA(1, 2);
      // bytes memory valAEncoded = abi.encode(valA);
      // BaseType memory valB = abi.decode(valAEncoded, (BaseType));
      // if (valB.kind == 1) {
      //   return "success";
      // } else {
      //   return "error";
      // }

      // compiler error: can't convert
      // ChildA memory valA = ChildA(1, 2);
      // BaseType memory base = BaseType(valA);
      // return "success";


      // ChildA memory valA = ChildA(1, ["one", "two"]);
      // ChildB memory valB = ChildB(2, [1, 2]);

      // BaseType[] memory values = new BaseType[](2);
      
      // values[0] = valA;
      // values[1] = valB;

      // ChildA memory casted = values[0];

      // return casted.values[0];
    }

    // pass-by-reference is possible
    // modify-in-place is possible for wrapper structs, arrays, and mappings.

    // An assignment or type conversion that changes the data location will always incur an automatic copy operation, while assignments inside the same data location only copy in some cases for storage types

    // Calldata is a non-modifiable, non-persistent area where function arguments are stored, and behaves mostly like memory. It is required for parameters of external functions but can also be used for other variables.


    struct StrArray {
      string[] items;
    }
    
    function popInpl(string[] memory items) public pure returns (string[] memory) {
      StrArray memory str = StrArray(items);
      arrPop(str);
      return str.items;
    }

    function arrPop(StrArray memory arr) public pure {
      if (arr.items.length < 1) {
        // do nothing
        return;
      } else if (arr.items.length == 1) {
        arr.items = new string[](0);
      } else { // length > 1
        uint newLength = arr.items.length - 1;
        string[] memory newItems = new string[](newLength);
        copy(arr.items, newItems);
        arr.items = newItems;
      }
    }

    function modifyInPlace(string[] memory items) public pure returns (string[] memory) {
      if (items.length <= 1) {
        
        // Type string memory[] memory is not implicitly convertible to expected type string calldata[] calldata.
        // string[] calldata ret = new string[](1);
        // error: Calldata arrays are read-only.
        // ret[0] = "one";
        // return ret;

        // doesn't work: memory is not implicitly convertible to expected type
        // return ["one"];

        string[] memory ret = new string[](1);
        ret[0] = "one";
        return ret;
      }
      // impossible to modify memory array, only re-allocate and copy
      items = pop(items);

      return modifyInPlace(items);
    }

    function pop(string[] memory items) public pure returns (string[] memory) {
      if (items.length < 1) {
        return items;
      } else if (items.length == 1) {
        return new string[](0);
      } else { // length > 1
        uint newLength = items.length - 1;
        string[] memory newItems = new string[](newLength);
        copy(items, newItems);
        return newItems;
      }
    }

    function copy(string[] memory from, string[] memory to) public pure {
      uint count = to.length < from.length ? to.length : from.length;
      uint i = 0;
      for (i = 0; i < count; i += 1) {
        to[i] = from[i];
      }
    }
}