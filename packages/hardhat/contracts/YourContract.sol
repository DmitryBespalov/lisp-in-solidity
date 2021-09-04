pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT

import "hardhat/console.sol";

contract YourContract {
    /*
        read inputString

        read tokens

        evaluates to expression
    */

    /*
    Input: string

    Output: 
        stream of tokens

    Input:
        stream of tokens

     Output:
     Expression Types
        ADDRESS,
        NUMBER,
        BOOL,
        SYMBOL,
        PROCEDURE,
        LIST
    
    */

    // Solidity strings may be UTF-8 but solidity doesn't provide
    // any functionality working with it.
    // We restrict the inputString to the ASCII strings

    // requires: ASCII string with SPIL expressions
    // guarantees:
    // AST created or reverts with error

    // convert string to array of tokens

    // convert string to bytes
    // implement DFA for parsing the string

    // ' ' -> skip
    // '(' -> start new list
    // ')' -> finalize the list
    // '0x' -> try read address: 0x[0-9a-fA-F]{40}<sep> <sep> = ws or '(' ')'
    // '0'-'9' -> try read number: [0-9]+ (max must fit to 32 bytes) ends with <sep>
    // not ' ' -> try read symbol: [....] <sep>
    // else unknown token, error

    function tokenize(string calldata str)
        public
        pure
        returns (Token[] memory)
    {
        // convert string to an array of string tokens
        bytes memory inputString = bytes(str);
        Token[] memory output;

        
        uint256 currentCharIndex = 0;
        
        // while not at the end of a string
        while (currentCharIndex < inputString.length) 
        {
            // get char
            bytes1 currentChar = inputString[ currentCharIndex ];
            
            // if space
            if ( currentChar == SYMBOL_SPACE ) 
            {
                // don't create any tokens for whitespace

                // skip the whitespace
                currentCharIndex += 1;

                // go to next char
                continue;
            }

            // if '(' then left parenthesis token
            if ( currentChar == SYMBOL_LEFT_PARENTHESIS ) 
            {
                Token memory token = Token( 
                    // type
                    TokenType.OPEN_PARENTHESIS, 
                    // value
                    "(", 
                    // location
                    currentCharIndex 
                );
                output = tokenPush(output, token);
                
                // skip '('
                currentCharIndex += 1;
                
                // go to next char
                continue;
            }

            // if ')' then right parenthesis token
            if ( currentChar == SYMBOL_RIGHT_PARENTHESIS ) 
            {
                Token memory token = Token( 
                    // type
                    TokenType.CLOSE_PARENTHESIS, 
                    // value
                    ")", 
                    // location
                    currentCharIndex 
                );
                output = tokenPush(output, token);
                
                // skip ')'
                currentCharIndex += 1;

                // go to next char
                continue;
            }

            // try parse address: regexp: 0x[0-9a-fA-F]{40}

            // if starts with '0x'
            bool isStartsWith0x = currentChar == SYMBOL_DIGIT_0 &&
                currentCharIndex + 1 < inputString.length &&
                inputString[currentCharIndex + 1] == SYMBOL_LOWER_X;

            if ( isStartsWith0x ) 
            {
                // collect hex address characters

                bytes memory hexAddressString;

                // skip '0x'
                uint256 addressCharIndex = currentCharIndex + 2;

                // read the potential hex address
                for (
                    // start index
                    addressCharIndex = currentCharIndex + 2;
                    
                    // is still inside input string?
                    addressCharIndex < inputString.length &&
                    hexAddressString.length < ADDRESS_SYMBOLS_LENGTH &&
                    isHexAddressChar( inputString[addressCharIndex] );

                    // increment to next char
                    addressCharIndex += 1
                )
                {
                    hexAddressString = bytesPush(hexAddressString, inputString[ addressCharIndex ]);
                }

                // check that we read an address: check size and that it is end of a token - then create address token
                if (
                    hexAddressString.length == ADDRESS_SYMBOLS_LENGTH &&
                    (
                        addressCharIndex >= inputString.length || isEndOfTokenChar( inputString[addressCharIndex] )
                    )
                ) 
                {
                    Token memory token = Token(
                        // type
                        TokenType.HEX_ADDRESS,
                        // value
                        string(hexAddressString),
                        // location of the start of the token
                        currentCharIndex
                    );

                    output = tokenPush(output, token);

                    // move past the address token
                    currentCharIndex = addressCharIndex;

                    // go to next char
                    continue;
                }
                else
                {
                    // this is not an address, try to recognize something else (fall through)
                }
            }

            // if '0-9' - try to recognize a number
            if ( isDigitChar( currentChar ) ) 
            {
                
                // collect number symbols
                bytes memory numberString;

                // collect digits into number string
                uint256 numberCharIndex = currentCharIndex;
                for (
                    numberCharIndex = currentCharIndex;

                    numberCharIndex < inputString.length && isDigitChar( inputString[numberCharIndex] );
                    
                    numberCharIndex += 1
                )
                {
                    numberString = bytesPush( numberString, inputString[ numberCharIndex ] );
                }

                // if next character is end of token character, then create token
                if (
                    numberCharIndex >= inputString.length ||
                    isEndOfTokenChar( inputString[numberCharIndex] )
                ) {
                    Token memory token = Token( 
                        // type
                        TokenType.NUMBER,
                        // value
                        string(numberString),
                        // location: start of the number token
                        currentCharIndex
                    );
                    output = tokenPush(output, token);

                    // jump to end of number string token
                    currentCharIndex = numberCharIndex;

                    // go to next char
                    continue;
                }
                else 
                {
                    // this is not a number, continue to try recognize something else (fall through).
                }
            }

            // try parsing symbol: all non-control characters except space.
            if ( isSymbolChar( currentChar ) )
            {
                bytes memory symbolString;

                uint256 symbolCharIndex = currentCharIndex;
                
                // collect symbols into string
                for(
                    symbolCharIndex = currentCharIndex;

                    symbolCharIndex < inputString.length && isSymbolChar( inputString[symbolCharIndex] );

                    symbolCharIndex += 1
                )
                {
                    symbolString = bytesPush(symbolString, inputString[ symbolCharIndex ]);
                }

                // if next char end of token then create token
                if (
                    symbolCharIndex >= inputString.length ||
                    isEndOfTokenChar( inputString[symbolCharIndex] )
                ) {
                    Token memory token = Token(
                        // type
                        TokenType.SYMBOL,
                        // value
                        string(symbolString),
                        // location: start of the symbol token
                        currentCharIndex
                    );
                    output = tokenPush(output, token);

                    // jump to the end of the symbol token
                    currentCharIndex = symbolCharIndex;

                    // go to next char
                    continue;
                }
                else
                {
                    // not a symbol, try recognizing something else
                }
            }

            // couldn't recognize this character, fail with error.
            revert SyntaxError(currentCharIndex);

        } // end of while loop

        return output;
    }

    function isHexAddressChar( bytes1 char )
      public 
      pure
      returns (bool)
    {
      return
          // is 0-9?
          isDigitChar( char ) ||
          // is a-f?
          char >= SYMBOL_LOWER_A && char <= SYMBOL_LOWER_F ||
          // is A-F?
          char >= SYMBOL_UPPER_A && char <= SYMBOL_UPPER_F
      ;
    }

    function isDigitChar( bytes1 char )
        public
        pure
        returns (bool)
    {
        return char >= SYMBOL_DIGIT_0 && char <= SYMBOL_DIGIT_9;
    }

    function isEndOfTokenChar( bytes1 char )
        public 
        pure
        returns (bool)
    {
        return
            char == SYMBOL_SPACE ||
            char == SYMBOL_LEFT_PARENTHESIS ||
            char == SYMBOL_RIGHT_PARENTHESIS; 
    }

    function isSymbolChar( bytes1 char )
        public
        pure
        returns (bool)
    {
        return char > SYMBOL_SPACE && char < SYMBOL_END_OF_ASCII && !isParenthesesChar( char );
        
    }

    function isParenthesesChar( bytes1 char )
        public
        pure
        returns (bool)
    {
        return char == SYMBOL_LEFT_PARENTHESIS || char == SYMBOL_RIGHT_PARENTHESIS;
    }

    enum TokenType {
        OPEN_PARENTHESIS,
        CLOSE_PARENTHESIS,
        HEX_ADDRESS,
        NUMBER,
        SYMBOL
    }

    struct Token {
        TokenType kind;
        string value;
        uint256 currentCharIndex;
    }

    error SyntaxError(uint256 byteLocation);

    bytes1 constant SYMBOL_SPACE = 0x20;
    bytes1 constant SYMBOL_LEFT_PARENTHESIS = 0x28;
    bytes1 constant SYMBOL_RIGHT_PARENTHESIS = 0x29;

    bytes1 constant SYMBOL_DIGIT_0 = 0x30;

    bytes1 constant SYMBOL_LOWER_X = 0x78;
    bytes1 constant SYMBOL_DIGIT_9 = 0x39;

    bytes1 constant SYMBOL_LOWER_A = 0x61;
    bytes1 constant SYMBOL_LOWER_F = 0x66;

    bytes1 constant SYMBOL_UPPER_A = 0x41;
    bytes1 constant SYMBOL_UPPER_F = 0x46;

    bytes1 constant SYMBOL_END_OF_ASCII = 0x7F;

    uint256 constant ADDRESS_SYMBOLS_LENGTH = 40;

    // copy-paste
    function tokenPush(Token[] memory list, Token memory entry)
        public
        pure
        returns (Token[] memory)
    {
        Token[] memory newList = new Token[](list.length + 1);
        // copy existing
        uint256 i = 0;
        for (i = 0; i < list.length; i += 1) {
            newList[i] = list[i];
        }
        newList[list.length] = entry;
        return newList;
    }

    // copy-paste
    function bytesPush(bytes memory list, bytes1 entry)
        public
        pure
        returns (bytes memory)
    {
        bytes memory newList = new bytes(list.length + 1);
        // copy existing
        uint256 i = 0;
        for (i = 0; i < list.length; i += 1) {
            newList[i] = list[i];
        }
        newList[list.length] = entry;
        return newList;
    }


    // convert token strings to expression AST
    function parseTokens(Token[] memory tokens)
        public
        pure
        returns (Expression memory)
    {

    }

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

        uint256 result = decodeNumber(
            evaluate(conditional, standardEnvironment())
        );

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

    // evaluate the AST
    function evaluate(
        Expression memory expression,
        Environment memory environment
    ) public view returns (Expression memory) {
        // switch is not available in Solidity, therefore using if-else
        if (expression.id == ExpressionType.ADDRESS) {
            return expression;
        } else if (expression.id == ExpressionType.NUMBER) {
            return expression;
        } else if (expression.id == ExpressionType.BOOL) {
            return expression;
        } else if (expression.id == ExpressionType.SYMBOL) {
            string memory symbol = decodeSymbol(expression);
            return getEnvironment(symbol, environment);
        } else if (expression.id == ExpressionType.LIST) {
            // convert to list expr
            Expression[] memory list = decodeList(expression);

            // must be non-empty
            assert(list.length > 0);

            // first item must be symbol
            string memory identifier = decodeSymbol(list[0]);

            // conditional = 'if' test_expr true_exp false_exp
            if (streq(identifier, "if")) {
                // must have 3 more expressions (4 items in the list in total)
                assert(list.length == 4);

                // eval(test_expr)
                bool conditionIsTrue = decodeBool(
                    evaluate(list[1], environment)
                );

                // if result is true, evaluate 'true' case, otherwise evaluate 'false' case
                if (conditionIsTrue) {
                    return evaluate(list[2], environment);
                } else {
                    return evaluate(list[3], environment);
                }
            } else if (streq(identifier, "define")) {
                // define - define the variable in the environment
                // insert or replace  the evaluated expression under the symbol

                assert(list.length == 3);

                // 2nd is symbol
                string memory symbol = decodeSymbol(list[1]);

                // 3rd (index 2) is the expression to evaluate.
                setEnvironment(
                    symbol,
                    environment,
                    evaluate(list[2], environment)
                );
            } else {
                // procedure call = <symbol> [<arg1> arg2 ...]
                // get procedure from first element evaluation
                bytes4 selector = decodeProcedure(
                    evaluate(list[0], environment)
                );

                // eval every argument to get list of expressions
                uint256 argC = list.length - 1;
                Expression[] memory args = new Expression[](argC);

                uint256 argIdx = 0;
                for (argIdx = 0; argIdx < argC; argIdx += 1) {
                    args[argIdx] = evaluate(list[1 + argIdx], environment);
                }

                // invoke call on this contract with the arguments
                bytes memory abiCall = abi.encodeWithSelector(selector, args);

                (bool success, bytes memory data) = address(this).staticcall(
                    abiCall
                );

                if (!success) {
                    revert("failed");
                }

                Expression memory result = abi.decode(data, (Expression));

                return result;
            }
        }
        revert("unknown expr id");
    }

    function streq(string memory lhs, string memory rhs)
        public
        pure
        returns (bool)
    {
        return
            keccak256(abi.encodePacked(lhs)) ==
            keccak256(abi.encodePacked(rhs));
    }

    function getEnvironment(
        string memory symbol,
        Environment memory environment
    ) public pure returns (Expression memory) {
        // find and return
        uint256 i = 0;
        for (i = 0; i < environment.entries.length; i += 1) {
            if (streq(environment.entries[i].key, symbol)) {
                return environment.entries[i].value;
            }
        }
        // error if not found
        revert("env not found");
    }

    function setEnvironment(
        string memory symbol,
        Environment memory environment,
        Expression memory value
    ) public pure {
        // find or append
        uint256 i = 0;
        for (i = 0; i < environment.entries.length; i += 1) {
            if (streq(environment.entries[i].key, symbol)) {
                environment.entries[i].value = value;
                return;
            }
        }
        // not found, set new value
        environment.entries = push(
            environment.entries,
            EnvironmentEntry(symbol, value)
        );
    }

    function push(EnvironmentEntry[] memory list, EnvironmentEntry memory entry)
        public
        pure
        returns (EnvironmentEntry[] memory)
    {
        EnvironmentEntry[] memory newList = new EnvironmentEntry[](
            list.length + 1
        );
        // copy existing
        uint256 i = 0;
        for (i = 0; i < list.length; i += 1) {
            newList[i] = list[i];
        }
        newList[list.length] = entry;
        return newList;
    }

    function standardEnvironment() public pure returns (Environment memory) {
        // EnvironmentEntry[] memory entries = new EnvironmentEntry[](0);
        EnvironmentEntry[] memory entries = new EnvironmentEntry[](2);
        // ==
        entries[0] = EnvironmentEntry(
            "==",
            // struct Expression[] -> (enum,bytes)[] -> (uint8, bytes)[]
            encodeProcedure(selectorOf("equals((uint8,bytes)[])"))
        );
        // !=
        entries[1] = EnvironmentEntry(
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
        return
            Expression(ExpressionType.BOOL, abi.encode(BoolExpression(value)));
    }

    function decodeBool(Expression memory expr) public pure returns (bool) {
        assert(expr.id == ExpressionType.BOOL);
        BoolExpression memory isTrue = abi.decode(expr.value, (BoolExpression));
        return isTrue.value;
    }

    function encodeAddress(address value)
        public
        pure
        returns (Expression memory)
    {
        return
            Expression(
                ExpressionType.ADDRESS,
                abi.encode(AddressExpression(value))
            );
    }

    function decodeAddress(Expression memory expr)
        public
        pure
        returns (address)
    {
        assert(expr.id == ExpressionType.ADDRESS);
        AddressExpression memory addressExpr = abi.decode(
            expr.value,
            (AddressExpression)
        );
        return addressExpr.value;
    }

    function encodeNumber(uint256 value)
        public
        pure
        returns (Expression memory)
    {
        return
            Expression(
                ExpressionType.NUMBER,
                abi.encode(NumberExpression(value))
            );
    }

    function decodeNumber(Expression memory expr)
        public
        pure
        returns (uint256)
    {
        assert(expr.id == ExpressionType.NUMBER);
        NumberExpression memory numExpr = abi.decode(
            expr.value,
            (NumberExpression)
        );
        return numExpr.value;
    }

    function encodeSymbol(string memory value)
        public
        pure
        returns (Expression memory)
    {
        return
            Expression(
                ExpressionType.SYMBOL,
                abi.encode(SymbolExpression(value))
            );
    }

    function decodeSymbol(Expression memory expr)
        public
        pure
        returns (string memory)
    {
        assert(expr.id == ExpressionType.SYMBOL);
        SymbolExpression memory symExpr = abi.decode(
            expr.value,
            (SymbolExpression)
        );
        return symExpr.value;
    }

    function encodeList(Expression[] memory items)
        public
        pure
        returns (Expression memory)
    {
        return
            Expression(ExpressionType.LIST, abi.encode(ListExpression(items)));
    }

    function decodeList(Expression memory expr)
        public
        pure
        returns (Expression[] memory)
    {
        assert(expr.id == ExpressionType.LIST);
        ListExpression memory listExpr = abi.decode(
            expr.value,
            (ListExpression)
        );
        return listExpr.items;
    }

    function encodeProcedure(bytes4 selector)
        public
        pure
        returns (Expression memory)
    {
        return
            Expression(
                ExpressionType.PROCEDURE,
                abi.encode(ProcedureExpression(selector))
            );
    }

    function decodeProcedure(Expression memory expr)
        public
        pure
        returns (bytes4)
    {
        assert(expr.id == ExpressionType.PROCEDURE);
        ProcedureExpression memory procExpr = abi.decode(
            expr.value,
            (ProcedureExpression)
        );
        return procExpr.selector;
    }

    // utils

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
        if (args.length != 2) {
            return encodeBool(false);
        }

        if (args[0].id != args[1].id) {
            return encodeBool(false);
        }

        if (args[0].id == ExpressionType.ADDRESS) {
            address lhs = decodeAddress(args[0]);
            address rhs = decodeAddress(args[1]);

            return encodeBool(lhs == rhs);
        } else if (args[0].id == ExpressionType.NUMBER) {
            uint256 lhs = decodeNumber(args[0]);
            uint256 rhs = decodeNumber(args[1]);

            return encodeBool(lhs == rhs);
        } else if (args[0].id == ExpressionType.BOOL) {
            bool lhs = decodeBool(args[0]);
            bool rhs = decodeBool(args[1]);

            return encodeBool(lhs == rhs);
        } else if (args[0].id == ExpressionType.SYMBOL) {
            string memory lhs = decodeSymbol(args[0]);
            string memory rhs = decodeSymbol(args[1]);

            return encodeBool(streq(lhs, rhs));
        } else if (args[0].id == ExpressionType.LIST) {
            // two lists are equal if they are the same length and same elements

            Expression[] memory lhs = decodeList(args[0]);
            Expression[] memory rhs = decodeList(args[1]);

            if (lhs.length != rhs.length) {
                return encodeBool(false);
            }

            uint256 i = 0;
            for (i = 0; i < lhs.length; i += 1) {
                Expression[] memory eqArgs = new Expression[](2);
                eqArgs[0] = lhs[i];
                eqArgs[1] = rhs[i];

                bool itemsIsEqual = decodeBool(equals(eqArgs));

                if (!itemsIsEqual) {
                    return encodeBool(false);
                }
            }

            return encodeBool(true);
        } else {
            return encodeBool(false);
        }
    }

    // (!= a b)
    function notEquals(Expression[] memory args)
        public
        pure
        returns (Expression memory)
    {
        bool isEqual = decodeBool(equals(args));
        return encodeBool(!isEqual);
    }
}
