pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT

// LICENSE: see LICENSE file in the project root.

import "hardhat/console.sol";

contract YourContract {

    // base type for representing token in the input string.
    struct Token {
        TokenType id;

        // the token string
        string value;

        // character index (ASCII) in the input string
        uint256 currentCharIndex;
    }

    enum TokenType {
        OPEN_PARENTHESIS,
        CLOSE_PARENTHESIS,
        HEX_ADDRESS,
        NUMBER,
        SYMBOL
    }

    // Wrapper for the array of tokens to pass between functions in order to modify it.
    struct TokenStream {
        Token[] tokens;
    }

    error SyntaxError(uint256 byteLocation);

    // ' '
    bytes1 constant SYMBOL_SPACE = 0x20;
    
    // '('
    bytes1 constant SYMBOL_LEFT_PARENTHESIS = 0x28;

    // ')'
    bytes1 constant SYMBOL_RIGHT_PARENTHESIS = 0x29;

    // '0'
    bytes1 constant SYMBOL_DIGIT_0 = 0x30;

    // '9'
    bytes1 constant SYMBOL_DIGIT_9 = 0x39;

    // 'x'
    bytes1 constant SYMBOL_LOWER_X = 0x78;

    // 'a'
    bytes1 constant SYMBOL_LOWER_A = 0x61;
    
    // 'f'
    bytes1 constant SYMBOL_LOWER_F = 0x66;

    // 'A'
    bytes1 constant SYMBOL_UPPER_A = 0x41;

    // 'F'
    bytes1 constant SYMBOL_UPPER_F = 0x46;

    // end of ascii range
    bytes1 constant SYMBOL_END_OF_ASCII = 0x7F;

    // 20 bytes x 2 hex chars per byte = 40 chars in the address
    uint256 constant ADDRESS_SYMBOLS_LENGTH = 40;


    // base 'class' - wrapper type for other expressions
    // classes are not available in Solidity, so we're using structs with enums.
    // other 'expression' types will be abi-encoded into `value`.
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

    struct ProcedureExpression {
        // cannot abi.encode or decode this
        // function (Expression[] memory) internal pure returns (Expression memory) fn;
        bytes4 selector;
    }

    // Environment is a lookup table of language's method names to method implementations
    struct Environment {
        EnvironmentEntry[] entries;
    }

    struct EnvironmentEntry {
        string key;
        Expression value;
    }

    // Main interpreter function. Input: string in the source language, output: evaluated expression.
    function interpret(string calldata str)
        public 
        view
        returns (Expression memory)
    {
        TokenStream memory stream = tokenize(str);
        Expression memory expression = parseTokens(stream);
        Expression memory result = evaluate(expression, standardEnvironment());
        return result;
    }

    // creates tokens from the input string
    function tokenize(string calldata str)
        public
        pure
        returns (TokenStream memory)
    {
        // ' ' -> skip
        // '(' -> start new list
        // ')' -> finalize the list
        // '0x' -> try read address: 0x[0-9a-fA-F]{40}<sep> <sep> = ws or '(' ')'
        // '0'-'9' -> try read number: [0-9]+ (max must fit to 32 bytes) ends with <sep>
        // not ' ' -> try read symbol: [....] <sep>
        // else unknown token, error

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

        TokenStream memory result = TokenStream(output);
        return result;
    }

    function isHexAddressChar( bytes1 char )
      private 
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
        private
        pure
        returns (bool)
    {
        return char >= SYMBOL_DIGIT_0 && char <= SYMBOL_DIGIT_9;
    }

    function isEndOfTokenChar( bytes1 char )
        private 
        pure
        returns (bool)
    {
        return
            char == SYMBOL_SPACE ||
            char == SYMBOL_LEFT_PARENTHESIS ||
            char == SYMBOL_RIGHT_PARENTHESIS; 
    }

    function isSymbolChar( bytes1 char )
        private
        pure
        returns (bool)
    {
        return char > SYMBOL_SPACE && char < SYMBOL_END_OF_ASCII && !isParenthesesChar( char );
        
    }

    function isParenthesesChar( bytes1 char )
        private
        pure
        returns (bool)
    {
        return char == SYMBOL_LEFT_PARENTHESIS || char == SYMBOL_RIGHT_PARENTHESIS;
    }

    // copy-paste (here and in other places with push/pop) because I couldn't figure out how to override the array management for different types
    function tokenPush(Token[] memory list, Token memory entry)
        private
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
        private
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

    function expressionPush(Expression[] memory list, Expression memory entry)
        private
        pure
        returns (Expression[] memory)
    {
        Expression[] memory newList = new Expression[](list.length + 1);
        // copy existing
        uint256 i = 0;
        for (i = 0; i < list.length; i += 1) {
            newList[i] = list[i];
        }
        newList[list.length] = entry;
        return newList;
    }

    function tokenStreamPopFirst(TokenStream memory stream)
        private
        pure
        returns (Token memory)
    {
        assert(stream.tokens.length > 0);
        Token memory result = stream.tokens[0];

        // create and copy reduced tokens
        Token[] memory newList = new Token[](stream.tokens.length - 1);
        uint256 i = 1;
        for (i = 1; i < stream.tokens.length; i += 1)
        {
            newList[i - 1] = stream.tokens[i];
        }
        // modify the list
        stream.tokens = newList;
        
        return result;
    }

    function tokenStreamPeekFirst(TokenStream memory stream)
        private
        pure
        returns (Token memory)
    {
        assert(stream.tokens.length > 0);
        Token memory result = stream.tokens[0];
        return result;
    }

    // convert token strings to expression AST
    function parseTokens(TokenStream memory stream)
        private
        pure
        returns (Expression memory)
    {
        // pop token
        Token memory token = tokenStreamPopFirst(stream);
        // HEX_ADDRESS,
        if ( token.id == TokenType.HEX_ADDRESS )
        {
            // convert string to bytes20 / address -> encodeAddress
            uint160 result = 0;
            
            // 0x231DE59a942909b8b8476B0E2a5b82b6D128e7B3
            bytes memory str = bytes(token.value);

            // we skipped the '0x' during parsing
            // assert(str.length == 42);
            // assert(str[0] == SYMBOL_DIGIT_0 && str[1] == SYMBOL_LOWER_X);

            assert(str.length == 40);

            uint256 charIndex = 0;
            for ( charIndex = 0; charIndex < str.length; charIndex += 1)
            {
                uint8 bits4 = hexCharToDecimalNumber( str[ charIndex ] );

                result *= 16;

                result += uint160(bits4);
            }

            // now we got the number, encode and return
            return encodeAddress( address(result) );
        }
        // NUMBER,
        else if ( token.id == TokenType.NUMBER )
        {
            // convert ascii digits to uint256 -> encodeNumber
            uint256 result = 0;

            bytes memory str = bytes(token.value);

            // 1233468929234234134
            uint256 charIndex = 0;
            for (charIndex = 0; charIndex < str.length; charIndex += 1)
            {
                uint8 bits4 = decimalCharToDecimalNumber( str[ charIndex ] );
                // can overflow
                result *= 10;
                // can overflow
                result += uint256(bits4);
            }

            return encodeNumber( result );
        }
        // SYMBOL
        else if ( token.id == TokenType.SYMBOL )
        {
            // use string as is -> encodeSymbol
            string memory result = token.value;
            return encodeSymbol( result );
        }
        // OPEN_PARENTHESIS,
        else if ( token.id == TokenType.OPEN_PARENTHESIS )
        {
            // create empty list expression
            Expression[] memory items = new Expression[](0);

            // add children via parsing until the close parenth token
                // while top is not a closed parenthesis
            while ( tokenStreamPeekFirst(stream).id != TokenType.CLOSE_PARENTHESIS )
            {
                    // parse next item, will pop the item.
                    Expression memory item = parseTokens(stream);
                    // add result to the items list
                    items = expressionPush(items, item);
            }
            // pop the close parenth token
            tokenStreamPopFirst(stream);
            
            return encodeList(items);
        }
        // CLOSE_PARENTHESIS,
        else if ( token.id == TokenType.CLOSE_PARENTHESIS )
        {
            // error - close parenthesis encountered
            revert("unexpected close parenthesis");
        }
        else 
        {
            revert("unrecognized token type");
        }
    }

    function hexCharToDecimalNumber( bytes1 char ) 
        private
        pure
        returns (uint8 number)
    {
        if ( char >= SYMBOL_DIGIT_0 && char <= SYMBOL_DIGIT_9 )
        {
            return uint8(char) - uint8(SYMBOL_DIGIT_0);
        }
        else if ( char >= SYMBOL_LOWER_A && char <= SYMBOL_LOWER_F )
        {
            return uint8(char) - uint8(SYMBOL_LOWER_A) + 10;
        }
        else if ( char >= SYMBOL_UPPER_A && char <= SYMBOL_UPPER_F )
        {
            return uint8(char) - uint8(SYMBOL_UPPER_A) + 10;
        }
        else 
        {
            revert("unrecognized hex char");
        }
    }

    function decimalCharToDecimalNumber( bytes1 char )
        private
        pure
        returns (uint8 number)
    {
        if ( char >= SYMBOL_DIGIT_0 && char <= SYMBOL_DIGIT_9 )
        {
            return uint8(char) - uint8(SYMBOL_DIGIT_0);
        }
        else
        {
            revert("unrecognized decimal char");
        }
    }

    // evaluate the AST
    function evaluate(
        Expression memory expression,
        Environment memory environment
    ) 
        private
        view 
        returns (Expression memory) 
    {
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
                Expression memory value = evaluate(list[2], environment);

                setEnvironment(
                    symbol,
                    environment,
                    value
                );

                return value;
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
        private
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
    ) 
        private 
        pure 
        returns (Expression memory) 
    {
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
    ) 
        private 
        pure 
    {
        // find or append
        uint256 i = 0;
        for (i = 0; i < environment.entries.length; i += 1) {
            if (streq(environment.entries[i].key, symbol)) {
                environment.entries[i].value = value;
                return;
            }
        }
        // not found, set new value
        environment.entries = environmentEntryPush(
            environment.entries,
            EnvironmentEntry(symbol, value)
        );
    }

    function environmentEntryPush(EnvironmentEntry[] memory list, EnvironmentEntry memory entry)
        private
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
    
    // creates a standard environment - mapping from language function names to implementations of these functions
    function standardEnvironment() 
        private 
        pure 
        returns (Environment memory) 
    {
        // EnvironmentEntry[] memory entries = new EnvironmentEntry[](0);
        EnvironmentEntry[] memory entries = new EnvironmentEntry[](0);
        // equal?
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "equal?",
                // struct Expression[] -> (enum,bytes)[] -> (uint8, bytes)[]
                encodeProcedure(selectorOf("equals((uint8,bytes)[])"))
            )
        );
        // not equal
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "not-equal?",
                encodeProcedure(selectorOf("notEquals((uint8,bytes)[])"))
            )
        );

        // number comparisons
        // = number equality
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "=",
                encodeProcedure(selectorOf("numberEquals((uint8,bytes)[])"))
            )
        );

        // <
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "<",
                encodeProcedure(selectorOf("lessThan((uint8,bytes)[])"))
            )
        );

        // >
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                ">",
                encodeProcedure(selectorOf("greaterThan((uint8,bytes)[])"))
            )
        );

        // <=
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "<=",
                encodeProcedure(selectorOf("lessThanOrEquals((uint8,bytes)[])"))
            )
        );

        // >=
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                ">",
                encodeProcedure(selectorOf("greaterThanOrEquals((uint8,bytes)[])"))
            )
        );

        // logical operators
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "and",
                encodeProcedure(selectorOf("boolAnd((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "or",
                encodeProcedure(selectorOf("boolOr((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "not",
                encodeProcedure(selectorOf("boolNot((uint8,bytes)[])"))
            )
        );

        // Arithmetic on numbers
        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "+",
                encodeProcedure(selectorOf("numberAdd((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "-",
                encodeProcedure(selectorOf("numberSubtract((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "*",
                encodeProcedure(selectorOf("numberMultiply((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "/",
                encodeProcedure(selectorOf("numberDivide((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "begin",
                encodeProcedure(selectorOf("begin((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "list",
                encodeProcedure(selectorOf("makeList((uint8,bytes)[])"))
            )
        );

        entries = environmentEntryPush(
            entries,
            EnvironmentEntry(
                "member",
                encodeProcedure(selectorOf("isMember((uint8,bytes)[])"))
            )
        );
        
        return Environment(entries);
    }

    // encoding / decoding AST types

    function encodeBool(bool value) 
        private 
        pure 
        returns (Expression memory) 
    {
        return
            Expression(ExpressionType.BOOL, abi.encode(BoolExpression(value)));
    }

    function decodeBool(Expression memory expr) 
        private 
        pure 
        returns (bool) 
    {
        assert(expr.id == ExpressionType.BOOL);
        BoolExpression memory isTrue = abi.decode(expr.value, (BoolExpression));
        return isTrue.value;
    }

    function encodeAddress(address value)
        private
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
        private
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
        private
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
        private
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
        private
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
        private
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
        private
        pure
        returns (Expression memory)
    {
        return
            Expression(ExpressionType.LIST, abi.encode(ListExpression(items)));
    }

    function decodeList(Expression memory expr)
        private
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
        private
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
        private
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

    function selectorOf(string memory signature) private pure returns (bytes4) {
        return bytes4(keccak256(bytes(signature)));
    }

    // Standard functions

    // (equal? a b) for terminals and lists, not for procedures
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

    // (not-equal? a b)
    function notEquals(Expression[] memory args)
        public
        pure
        returns (Expression memory)
    {
        bool isEqual = decodeBool(equals(args));
        return encodeBool(!isEqual);
    }

    // (< a b)
    // only works on numbers
    function lessThan(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeBool(lhs < rhs);
    }

    // (> a b)
    function greaterThan(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeBool(lhs > rhs);
    }

    // (<= a b)
    function lessThanOrEquals(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeBool(lhs <= rhs);
    }

    // (>= a b)
    function greaterThanOrEquals(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeBool(lhs >= rhs);
    }

    // (== a b)
    function numberEquals(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeBool(lhs == rhs);
    }

    // (+ a b)
    function numberAdd(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeNumber(lhs + rhs);
    }

    // (- a b)
    function numberSubtract(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeNumber(lhs - rhs);
    }

    // (* a b)
    function numberMultiply(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeNumber(lhs * rhs);
    }

    // (/ a b)
    function numberDivide(Expression[] memory args)
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

        if (args[0].id != ExpressionType.NUMBER)
        {
            return encodeBool(false);
        }

        uint256 lhs = decodeNumber(args[0]);
        uint256 rhs = decodeNumber(args[1]);

        return encodeNumber(lhs / rhs);
    }

    //  Logical Operations

    // (and a b)
    function boolAnd(Expression[] memory args)
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

        if (args[0].id != ExpressionType.BOOL)
        {
            return encodeBool(false);
        }

        bool lhs = decodeBool(args[0]);
        bool rhs = decodeBool(args[1]);

        return encodeBool(lhs && rhs);
    }

    // (or a b)
    function boolOr(Expression[] memory args)
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

        if (args[0].id != ExpressionType.BOOL)
        {
            return encodeBool(false);
        }

        bool lhs = decodeBool(args[0]);
        bool rhs = decodeBool(args[1]);

        return encodeBool(lhs || rhs);
    }

    // (not a)
    function boolNot(Expression[] memory args)
        public
        pure
        returns (Expression memory)
    {
        if (args.length != 1) 
        {
            return encodeBool(false);
        }

        if (args[0].id != ExpressionType.BOOL)
        {
            return encodeBool(false);
        }

        bool lhs = decodeBool(args[0]);

        return encodeBool( !lhs );
    }

    // begin evals every argument in order and returns final one
    // 
    // every argument is already evaluated by the interpreter,
    // so we will return the final one.
    function begin(Expression[] memory args)
        public
        pure
        returns (Expression memory)
    {
        if (args.length == 0)
        {
            revert("begin without arguments");
        }
        
        return args[args.length - 1];
    }

    function makeList(Expression[] memory args)
        public
        pure
        returns (Expression memory)
    {
        return encodeList(args);
    }

    // (membe? value list)
    // true if list contains value, false if it doesn't
    function isMember(Expression[] memory args)
        public
        pure
        returns (Expression memory)
    {
        if (args.length != 2)
        {
            return encodeBool(false);
        }

        // get list's contents
        Expression[] memory list = decodeList(args[1]);

        // check if any item equals to the first arg
        uint256 i = 0;
        for ( i = 0; i < list.length; i += 1)
        {
            Expression[] memory eqArgs = new Expression[](2);
            eqArgs[0] = args[0];
            eqArgs[1] = list[i];

            bool itemsIsEqual = decodeBool(equals(eqArgs));
            
            if (itemsIsEqual) {
                return encodeBool(true);
            }
        }

        // return false if nothing found
        return encodeBool(false);
    }
}
