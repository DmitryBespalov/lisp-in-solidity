pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT

import "hardhat/console.sol";

contract YourContract {

    /*
        read input

        read tokens

        evaluates to expression
    */

    function tryOutEval() public view returns (uint256) {
        // (if (== 2 2) 1 2)
        Expression memory _1 = encodeNumber(1);
        Expression memory _2 = encodeNumber(2);

        Expression memory _hello = encodeNumber(2);
        Expression memory _world = encodeNumber(2);

        Expression memory _eq = encodeSymbol("==");

        Expression memory _if = encodeSymbol("if");

        Expression[] memory condExprs = new Expression[](3);
        condExprs[0] = _eq;
        condExprs[1] = _hello;
        condExprs[2] = _world;
        Expression memory condition = encodeList(condExprs);

        Expression[] memory _ifExprs = new Expression[](4);
        _ifExprs[0] = _if;
        _ifExprs[1] = condition;
        _ifExprs[2] = _1;
        _ifExprs[3] = _2;
        Expression memory conditional = encodeList(_ifExprs);

        uint256 result = decodeNumber( evaluate(conditional, standardEnvironment()) );

        return result;
    }

    /*

    def eval(x: Exp, env=global_env) -> Exp:
    "Evaluate an expression in an environment."
    if isinstance(x, Symbol):        # variable reference
        return env[x]
    elif isinstance(x, Number):      # constant number
        return x                
    elif x[0] == 'if':               # conditional (list)
        (_, test, conseq, alt) = x
        exp = (conseq if eval(test, env) else alt)
        return eval(exp, env)
    elif x[0] == 'define':           # definition (list)
        (_, symbol, exp) = x
        env[symbol] = eval(exp, env)
    else:                            # procedure call (list)
        proc = eval(x[0], env)
        args = [eval(arg, env) for arg in x[1:]]
        return proc(*args)
        */

    // envirnoment is a symbol lookup table 
    // that can reference by string variables or functions
    // to wrap the value we can use a struct wrapper because the 
    // solidity is static type.
    // or we can use the lookup only for variables... 
    // even then we would need to convert variables to some type.

    // address expression
    struct AddressExpression {
        address value;
    }
    
    // uint256 number expression
    struct NumberExpression {
        uint256 value;
    }

    // bool expression
    struct BoolExpression {
        bool value;
    }

    // a reference to a variable or a function in the execution environment
    struct SymbolExpression {
        string value;
    }

    // expression with multiple elements
    struct ListExpression {
        Expression[] items;
    }

    // base class - wrapper type for other expressions
    // classes are not available, so we're using structs
    // other 'expression' types will be abi-encoded into bytes.
    struct Expression {
        ExpressionType id;
        bytes value;
    }

    enum ExpressionType {
        ADDRESS,
        NUMBER,
        BOOL,
        SYMBOL,
        PROCEDURE,
        LIST
    }

    struct ProcedureExpression {
        // cannot abi.encode or decode this
        // function (Expression[] memory) internal pure returns (Expression memory) fn;
        bytes4 selector;
    }

    struct Environment {
        EnvironmentEntry[] entries;
    }

    struct EnvironmentEntry {
        string key;
        Expression value;
    }

    function evaluate(Expression memory expression, Environment memory environment) 
        public 
        view 
        returns (Expression memory) 
    {
        // switch is not available in Solidity, therefore using if-else
        if (expression.id == ExpressionType.ADDRESS) 
        {
            return expression;
        } 
        else if (expression.id == ExpressionType.NUMBER) 
        {
            return expression;
        } 
        else if (expression.id == ExpressionType.BOOL) 
        {
            return expression;
        } 
        else if (expression.id == ExpressionType.SYMBOL) 
        {
            string memory symbol = decodeSymbol( expression );
            return getEnvironment(symbol, environment);
        } 
        else if (expression.id == ExpressionType.LIST) 
        {

            // convert to list expr
            Expression[] memory list = decodeList( expression );
            
            // must be non-empty
            assert(list.length > 0);

            // first item must be symbol
            string memory identifier = decodeSymbol( list[0] );

            // conditional = 'if' test_expr true_exp false_exp
            if ( streq(identifier, "if") ) 
            {
                // must have 3 more expressions (4 items in the list in total)
                assert(list.length == 4);

                // eval(test_expr)
                bool conditionIsTrue = decodeBool( evaluate( list[1], environment ) );

                // if result is true, evaluate 'true' case, otherwise evaluate 'false' case
                if (conditionIsTrue) {
                    return evaluate(list[2], environment);
                } else {
                    return evaluate(list[3], environment);
                }
            }
            else if ( streq(identifier, "define") )
            {
                // define - define the variable in the environment
                // insert or replace  the evaluated expression under the symbol

                assert(list.length == 3);
                
                // 2nd is symbol
                string memory symbol = decodeSymbol( list[1] );

                // 3rd (index 2) is the expression to evaluate.
                setEnvironment(symbol, environment, evaluate(list[2], environment));
            } 
            else 
            {
                // procedure call = <symbol> [<arg1> arg2 ...]
                // get procedure from first element evaluation
                bytes4 selector = decodeProcedure( evaluate( list[0], environment ) );

                // eval every argument to get list of expressions                
                uint argC = list.length - 1;
                Expression[] memory args = new Expression[](argC);

                uint argIdx = 0;
                for ( argIdx = 0; argIdx < argC; argIdx += 1) {
                    args[argIdx] = evaluate(list[1 + argIdx], environment);
                }

                // invoke call on this contract with the arguments
                bytes memory abiCall = abi.encodeWithSelector(selector, args);

                (bool success, bytes memory data) = address(this).staticcall(abiCall);
                
                if ( !success ) {
                    revert("failed");
                }

                Expression memory result = abi.decode(data, (Expression));
                
                return result;
            }
        }
        revert("unknown expr id");
    }

    function streq(string memory lhs, string memory rhs) public pure returns (bool) {
        return keccak256(abi.encodePacked(lhs)) == keccak256(abi.encodePacked(rhs));
    }

    function getEnvironment(string memory symbol, Environment memory environment) 
        public
        pure
        returns (Expression memory)
    {   
        // find and return
        uint i = 0;
        for (i = 0; i < environment.entries.length; i += 1)
        {
            if ( streq(environment.entries[i].key, symbol) ) {
                return environment.entries[i].value;
            }
        }
        // error if not found
        revert("env not found");
    }

    function setEnvironment(string memory symbol, Environment memory environment, Expression memory value) 
        public
        pure
    {
        // find or append
        uint i = 0;
        for (i = 0; i < environment.entries.length; i += 1)
        {
            if ( streq(environment.entries[i].key, symbol) ) {
                environment.entries[i].value = value;
                return;
            }
        }
        // not found, set new value
        environment.entries = push( environment.entries, EnvironmentEntry(symbol, value) );
    }
    
    function push(EnvironmentEntry[] memory list, EnvironmentEntry memory entry) 
        public
        pure
        returns (EnvironmentEntry[] memory)
    {
        EnvironmentEntry[] memory newList = new EnvironmentEntry[](list.length + 1);
        newList[list.length] = entry;
        return newList;
    }

    function standardEnvironment()
        public 
        pure
        returns (Environment memory)
    {
        // EnvironmentEntry[] memory entries = new EnvironmentEntry[](0);
        EnvironmentEntry[] memory entries = new EnvironmentEntry[](2);
        // ==
        entries[0] = 
            EnvironmentEntry(
                "==",
                // struct Expression[] -> (enum,bytes)[] -> (uint8, bytes)[]
                encodeProcedure(selectorOf("equals((uint8,bytes)[])"))
            );
        // !=
        entries [1] = 
            EnvironmentEntry(
                "!=",
                encodeProcedure(selectorOf("notEquals((uint8,bytes)[])"))
            );

        return Environment(entries);
        // <
        // >
        // <=
        // >=
        // &&
        // ||
        // !
        // +
        // -
        // *
        // /
        // abs
        // list
        // contains

        // <tx signers> - read calldata
        // <safe owners> - read storage
    }

    // encoding / decoding AST types

    function encodeBool(bool value) public pure returns (Expression memory) {
        return Expression(ExpressionType.BOOL, abi.encode(BoolExpression(value)));
    }

    function decodeBool(Expression memory expr) public pure returns (bool) {
        assert(expr.id == ExpressionType.BOOL);
        BoolExpression memory isTrue = abi.decode(expr.value, (BoolExpression));
        return isTrue.value;
    }

    function encodeAddress(address value) public pure returns (Expression memory) {
        return Expression(ExpressionType.ADDRESS, abi.encode(AddressExpression(value)));
    }

    function decodeAddress(Expression memory expr) public pure returns (address) {
        assert(expr.id == ExpressionType.ADDRESS);
        AddressExpression memory addressExpr = abi.decode(expr.value, (AddressExpression));
        return addressExpr.value;
    }

    function encodeNumber(uint256 value) public pure returns (Expression memory) {
        return Expression(ExpressionType.NUMBER, abi.encode(NumberExpression(value)));
    }

    function decodeNumber(Expression memory expr) public pure returns (uint256) {
        assert(expr.id == ExpressionType.NUMBER);
        NumberExpression memory numExpr = abi.decode(expr.value, (NumberExpression));
        return numExpr.value;
    }

    function encodeSymbol(string memory value) public pure returns (Expression memory) {
        return Expression(ExpressionType.SYMBOL, abi.encode(SymbolExpression(value)));
    }

    function decodeSymbol(Expression memory expr) public pure returns (string memory) {
        assert(expr.id == ExpressionType.SYMBOL);
        SymbolExpression memory symExpr = abi.decode(expr.value, (SymbolExpression));
        return symExpr.value;
    }

    function encodeList(Expression[] memory items) public pure returns (Expression memory) {
        return Expression(ExpressionType.LIST, abi.encode(ListExpression(items)));
    }

    function decodeList(Expression memory expr) public pure returns (Expression[] memory) {
        assert(expr.id == ExpressionType.LIST);
        ListExpression memory listExpr = abi.decode(expr.value, (ListExpression));
        return listExpr.items;
    }

    function encodeProcedure(bytes4 selector) public pure returns (Expression memory) {
        return Expression(ExpressionType.PROCEDURE, abi.encode(ProcedureExpression( selector )));
    }

    function decodeProcedure(Expression memory expr) public pure returns (bytes4) {
        assert(expr.id == ExpressionType.PROCEDURE);
        ProcedureExpression memory procExpr = abi.decode(expr.value, (ProcedureExpression));
        return procExpr.selector;
    }

    function selectorOf(string memory signature) public pure returns (bytes4) {
        return bytes4(keccak256(bytes(signature)));
    }

    // Standard functions
    
    // (== a b) for terminals and lists, not for procedures
    function equals(Expression[] memory args) 
        public
        pure 
        returns (Expression memory) 
    {
        if (args.length != 2) 
        {
            return encodeBool(false);
        }

        if (args[0].id != args[1].id) 
        {
            return encodeBool(false);
        }
        
        if (args[0].id == ExpressionType.ADDRESS) 
        {
            address lhs = decodeAddress(args[0]);
            address rhs = decodeAddress(args[1]);
        
            return encodeBool(lhs == rhs); 
        } 
        else if (args[0].id == ExpressionType.NUMBER) 
        {
            uint256 lhs = decodeNumber(args[0]);
            uint256 rhs = decodeNumber(args[1]);
                
            return encodeBool(lhs == rhs);
        } 
        else if (args[0].id == ExpressionType.BOOL) 
        {       
            bool lhs = decodeBool(args[0]);
            bool rhs = decodeBool(args[1]);
                
            return encodeBool(lhs == rhs);
        } 
        else if (args[0].id == ExpressionType.SYMBOL) 
        {
            string memory lhs = decodeSymbol(args[0]);
            string memory rhs = decodeSymbol(args[1]);
                
            return encodeBool( streq(lhs, rhs) );
        } 
        else if (args[0].id == ExpressionType.LIST) 
        {
            // two lists are equal if they are the same length and same elements

            Expression[] memory lhs = decodeList(args[0]);
            Expression[] memory rhs = decodeList(args[1]);
            
            if (lhs.length != rhs.length) 
            {
                return encodeBool(false);
            }
            
            uint i = 0;
            for ( i = 0; i < lhs.length; i += 1 ) 
            {
                Expression[] memory eqArgs = new Expression[](2);
                eqArgs[0] = lhs[i];
                eqArgs[1] = rhs[i];

                bool itemsIsEqual = decodeBool( equals( eqArgs ) );

                if ( !itemsIsEqual ) 
                {
                    return encodeBool(false);
                }
            }
            
            return encodeBool(true);
        } 
        else 
        {
            return encodeBool(false);
        }
    }

    // (!= a b)
    function notEquals(Expression[] memory args) 
        public
        pure 
        returns (Expression memory) 
    {
        bool isEqual = decodeBool( equals( args ) );
        return encodeBool( !isEqual );
    }
    
}
