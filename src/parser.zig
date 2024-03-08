const std = @import("std");

const Lexer = @import("lexer.zig").Lexer;
const Token = @import("token.zig").Token;
const ast = @import("ast.zig");

const assert = std.debug.assert;

pub const Parser = struct {
    const ParseErr = error{
        OutOfMemory,
    };

    const Precedence = enum {
        LOWEST,
        EQUALS, //==
        LESSGREATER, //> or <
        SUM, // +
        PRODUCT, //*
        PREFIX, //-X or !X
        CALL, // myFunc(X)
    };

    //precedence table
    const precedence_table = std.ComptimeStringMap(Precedence, .{
        .{ @tagName(.EQ), .EQUALS },
        .{ @tagName(.NOT_EQ), .EQUALS },
        .{ @tagName(.LT), .LESSGREATER },
        .{ @tagName(.GT), .LESSGREATER },
        .{ @tagName(.PLUS), .SUM },
        .{ @tagName(.MINUS), .SUM },
        .{ @tagName(.SLASH), .PRODUCT },
        .{ @tagName(.ASTERISK), .PRODUCT },
        .{ @tagName(.LPAREN), .CALL },
    });

    //pointers for nodes of the AST are stored in these arrays
    const PointerStore = struct {
        let_statements: std.ArrayList(*ast.LetStatement),
        return_statements: std.ArrayList(*ast.ReturnStatement),
        expression_statements: std.ArrayList(*ast.ExpressionStatement),
        expressions: std.ArrayList(*ast.Expression),
        block_statements: std.ArrayList(*ast.BlockStatement),
    };

    //lexer member field
    lexer: Lexer,

    //token of the current position of the cursor
    current_token: Token = undefined,
    //look ahead token of the current_token or EOF if out of input
    peek_token: Token = undefined,
    //allocator, passed in by caller
    allocator: std.mem.Allocator,
    //program is set when parseProgram is called, contains the root of AST
    program: ast.Program,

    //memory store of AST
    pointer_store: PointerStore,
    //array of error strings produced by the parser
    errors: std.ArrayList([]const u8),

    //function defs for prefix/infix func callbacks, returns an index to an expression node
    const prefix_fn = *const (fn (*Parser) ParseErr!?u32);
    const infix_fn = *const (fn (*Parser, ?u32) ParseErr!?u32);

    //lookup table to get a function from a token type for prefix parsing
    const prefix_parse_fns = std.ComptimeStringMap(prefix_fn, .{
        .{ @tagName(.IDENT), Parser.parseIdentifier },
        .{ @tagName(.INT), Parser.parseIntegerLiteral },
        .{ @tagName(.BANG), Parser.parsePrefixExpression },
        .{ @tagName(.MINUS), Parser.parsePrefixExpression },
        .{ @tagName(.TRUE), Parser.parseBoolean },
        .{ @tagName(.FALSE), Parser.parseBoolean },
        .{ @tagName(.LPAREN), Parser.parseGroupedExpression },
        .{ @tagName(.IF), Parser.parseIfExpression },
        .{ @tagName(.FUNCTION), Parser.parseFunctionLiteral },
    });

    //lookup table to get a function from a token type for infix parsing
    const infix_parse_fns = std.ComptimeStringMap(infix_fn, .{
        .{ @tagName(.PLUS), Parser.parseInfixExpression },
        .{ @tagName(.MINUS), Parser.parseInfixExpression },
        .{ @tagName(.SLASH), Parser.parseInfixExpression },
        .{ @tagName(.ASTERISK), Parser.parseInfixExpression },
        .{ @tagName(.EQ), Parser.parseInfixExpression },
        .{ @tagName(.NOT_EQ), Parser.parseInfixExpression },
        .{ @tagName(.LT), Parser.parseInfixExpression },
        .{ @tagName(.GT), Parser.parseInfixExpression },
        .{ @tagName(.LPAREN), Parser.parseCallExpression },
    });

    //create a new paser, input is a the string to parse into an AST
    pub fn init(input: []const u8, allocator: std.mem.Allocator) Parser {
        var parser = Parser{
            .lexer = Lexer.init(input),
            .allocator = allocator,
            .program = ast.Program.init(allocator),
            .errors = std.ArrayList([]const u8).init(allocator),
            .pointer_store = .{
                .let_statements = std.ArrayList(*ast.LetStatement).init(allocator),
                .return_statements = std.ArrayList(*ast.ReturnStatement).init(allocator),
                .expression_statements = std.ArrayList(*ast.ExpressionStatement).init(allocator),
                .expressions = std.ArrayList(*ast.Expression).init(allocator),
                .block_statements = std.ArrayList(*ast.BlockStatement).init(allocator),
            },
        };

        //initialize tokens with input
        parser.nextToken();
        parser.nextToken();

        return parser;
    }

    //free any resources created by the parser
    pub fn deinit(self: *Parser) void {
        //clear any arrays stored in a node
        for (self.pointer_store.expressions.items) |e| {
            switch (e.*) {
                .function_literal => |*func| func.parameters.clearAndFree(),
                .call_expression => |*call| call.arguments.deinit(),

                else => {},
            }
        }

        //clear the allocated nodes for each type
        for (self.pointer_store.let_statements.items) |l| self.allocator.destroy(l);
        for (self.pointer_store.return_statements.items) |r| self.allocator.destroy(r);
        for (self.pointer_store.expression_statements.items) |e| self.allocator.destroy(e);
        for (self.pointer_store.expressions.items) |e| self.allocator.destroy(e);
        for (self.pointer_store.block_statements.items) |b| {
            b.statements.clearAndFree();
            self.allocator.destroy(b);
        }

        //clear to node arrays
        self.pointer_store.let_statements.deinit();
        self.pointer_store.return_statements.deinit();
        self.pointer_store.expression_statements.deinit();
        self.pointer_store.expressions.deinit();
        self.pointer_store.block_statements.deinit();

        self.program.deinit();

        for (self.errors.items) |err| self.allocator.free(err);
        self.errors.deinit();
    }

    //start parsing the input
    pub fn parseProgram(self: *Parser) ast.Program {
        while (self.current_token.type != .EOF) : (self.nextToken()) {
            const stmt = self.parseStatement() catch @panic("ERR");
            if (stmt) |s| self.program.statements.append(s) catch @panic("OOM");
        }

        return self.program;
    }

    //move the parser cursor forward, consuming the next token into the current and look ahead token
    fn nextToken(self: *Parser) void {
        self.current_token = self.peek_token;
        self.peek_token = self.lexer.nextToken();
    }

    //top level parser entrypoints
    fn parseStatement(self: *Parser) ParseErr!?ast.Node {
        return switch (self.current_token.type) {
            .LET => try self.parseLetStatement(),
            .RETURN => try self.parseReturnStatement(),
            else => try self.parseExpressionStatement(),
        };
    }

    //return an array of nodes based on the type of the node
    fn getTgtArr(self: *Parser, comptime T: type) *std.ArrayList(*T) {
        return switch (T) {
            ast.LetStatement => &self.pointer_store.let_statements,
            ast.ReturnStatement => &self.pointer_store.return_statements,
            ast.ExpressionStatement => &self.pointer_store.expression_statements,
            ast.Expression => &self.pointer_store.expressions,
            ast.BlockStatement => &self.pointer_store.block_statements,
            else => @panic("Cannot handle type: " ++ @typeName(T)),
        };
    }

    //add a new node to the in memory array store, returning its index
    //the array is selected based on the type of the new node
    fn addNode(self: *Parser, comptime T: type) error{OutOfMemory}!u32 {
        var tgt_arr = self.getTgtArr(T);
        const statement = try self.allocator.create(T);
        try tgt_arr.append(statement);

        return @as(u32, @truncate(tgt_arr.items.len - 1));
    }

    //add an existing node on the stack to the heap
    //the array is selected based on the type of the new node
    fn addExistingNode(self: *Parser, comptime T: type, existing: T) ParseErr!u32 {
        var tgt_arr = self.getTgtArr(T);
        const statement = try self.allocator.create(T);
        statement.* = existing;

        try tgt_arr.append(statement);
        return @as(u32, @truncate(tgt_arr.items.len - 1));
    }

    //get a node based on the index and the type of the node
    fn getNode(self: *Parser, index: u32, comptime T: type) *T {
        const tgt_arr = self.getTgtArr(T);

        assert(index < tgt_arr.items.len);
        return tgt_arr.items[index];
    }

    //entry point for parsing let statements
    //a let is: "let <expression>;"
    fn parseLetStatement(self: *Parser) ParseErr!?ast.Node {
        const let_statement_index = try self.addNode(ast.LetStatement);
        const stmt = ast.Node{ .let_statement = let_statement_index };
        var let_statement = self.getNode(let_statement_index, ast.LetStatement);
        let_statement.token = self.current_token;

        if (!self.expectPeek(.IDENT)) return null;

        let_statement.name = ast.Identifier{ .value = self.current_token.literal, .token = self.current_token };

        if (!self.expectPeek(.ASSIGN)) return null;

        self.nextToken();
        const expr_maybe = try self.parseExpression(.LOWEST);
        if (expr_maybe) |expr| let_statement.value = expr;

        if (self.peek_token.type == .SEMICOLON) {
            self.nextToken();
        }

        return stmt;
    }

    //entry point for parsing return statements
    //a return is: "return <expression>;
    fn parseReturnStatement(self: *Parser) ParseErr!?ast.Node {
        const return_statement_index = try self.addNode(ast.ReturnStatement);
        const stmt = ast.Node{ .return_statement = return_statement_index };
        var return_statement = self.getNode(return_statement_index, ast.ReturnStatement);
        return_statement.token = self.current_token;

        self.nextToken();

        const expr_maybe = try self.parseExpression(.LOWEST);
        if (expr_maybe) |expr| return_statement.return_value = expr;

        if (self.peek_token.type == .SEMICOLON) self.nextToken();

        return stmt;
    }

    //entry point of parsing expression statements, an expression_statement is a wrapper for an expression
    //the expression_statement sits inside the Node struct, this could be removed and the node just holds
    //the index to an expression but this lines up closer to the go implementation
    fn parseExpressionStatement(self: *Parser) ParseErr!?ast.Node {
        const expression_statement_index = try self.addNode(ast.ExpressionStatement);
        const stmt = ast.Node{ .expression_statement = expression_statement_index };
        var expression_statement = self.getNode(expression_statement_index, ast.ExpressionStatement);
        expression_statement.token = self.current_token;

        const expression_index_maybe = try self.parseExpression(.LOWEST);
        expression_statement.expression = if (expression_index_maybe) |expression_index| self.getNode(expression_index, ast.Expression).* else null;

        if (self.peek_token.type == .SEMICOLON) self.nextToken();

        return stmt;
    }

    //helper for parsing expressions, returns an options index to an expression node
    fn parseExpression(self: *Parser, prec: Precedence) !?u32 {
        const prefix_maybe = Parser.prefix_parse_fns.get(@tagName(self.current_token.type));
        if (prefix_maybe == null) {
            try self.noPrefixParseFnErr(self.current_token.type);
            return null;
        }

        const prefix = prefix_maybe.?;
        var left_expr = try prefix(self);

        while (self.peek_token.type != .SEMICOLON and @intFromEnum(prec) < @intFromEnum(self.peekPrecedence())) {
            const infix_maybe = Parser.infix_parse_fns.get(@tagName(self.peek_token.type));
            if (infix_maybe == null) return left_expr;

            self.nextToken();
            left_expr = try infix_maybe.?(self, left_expr);
        }

        return left_expr;
    }

    //append an error if no prefix callback was found for a token
    fn noPrefixParseFnErr(self: *Parser, token: Token.Type) !void {
        const msg = try std.fmt.allocPrint(self.allocator, "no prefix parse function for '{s}' found", .{@tagName(token)});
        try self.errors.append(msg);
    }

    //test if the look ahead token is an expected value, if so move the input forward
    fn expectPeek(self: *Parser, expected: Token.Type) bool {
        if (self.peek_token.type == expected) {
            self.nextToken();
            return true;
        }

        self.peekError(expected) catch @panic("OOM");
        return false;
    }

    //append an error when we have an unexpected token type
    fn peekError(self: *Parser, expected: Token.Type) !void {
        const msg = try std.fmt.allocPrint(self.allocator, "expected token of '{s}', got '{s}' instead", .{ @tagName(expected), @tagName(self.peek_token.type) });
        try self.errors.append(msg);
    }

    //prefix parsing functions for identifiers, returns an optional index to an expression
    fn parseIdentifier(self: *Parser) error{OutOfMemory}!?u32 {
        const expression = ast.Expression{
            .identifier = ast.Identifier{ .token = self.current_token, .value = self.current_token.literal },
        };
        return try self.addExistingNode(ast.Expression, expression);
    }

    //prefix parsing functions for integer literals, returns an optional index to an expression
    fn parseIntegerLiteral(self: *Parser) ParseErr!?u32 {
        const val = std.fmt.parseInt(i64, self.current_token.literal, 10) catch |err| {
            const str = std.fmt.allocPrint(self.allocator, "failed to parse '{s}' to an integer: {!}", .{ self.current_token.literal, err }) catch "failed to parse integer";
            try self.errors.append(str);
            return null;
        };

        const integer = ast.IntegerLiteral{ .value = val, .token = self.current_token };
        const expression = ast.Expression{ .integer_literal = integer };
        return try self.addExistingNode(ast.Expression, expression);
    }

    //entry point for parsing prefix expressions, returns an optional index to an expression
    fn parsePrefixExpression(self: *Parser) ParseErr!?u32 {
        const curr_token = self.current_token;
        self.nextToken();

        const prefix_expression = ast.PrefixExpression{ .token = curr_token, .operator = curr_token.literal, .right = try self.parseExpression(.PREFIX) };
        const expression = ast.Expression{ .prefix_expression = prefix_expression };
        return try self.addExistingNode(ast.Expression, expression);
    }

    //infix expression entry point
    fn parseInfixExpression(self: *Parser, left: ?u32) ParseErr!?u32 {
        const curr_token = self.current_token;
        const precedence = self.currentPrecendence();
        self.nextToken();

        const infix_expression = ast.InfixExpression{ .token = curr_token, .operator = curr_token.literal, .left = left, .right = try self.parseExpression(precedence) };
        const expression = ast.Expression{ .infix_expression = infix_expression };
        return try self.addExistingNode(ast.Expression, expression);
    }

    //get the precedence of the next token
    fn peekPrecedence(self: *Parser) Precedence {
        return Parser.precedence_table.get(@tagName(self.peek_token.type)) orelse .LOWEST;
    }

    //get the precedence of the current token
    fn currentPrecendence(self: *Parser) Precedence {
        return Parser.precedence_table.get(@tagName(self.peek_token.type)) orelse .LOWEST;
    }

    //boolean literals
    fn parseBoolean(self: *Parser) ParseErr!?u32 {
        const boolean = ast.Boolean{ .token = self.current_token, .value = (self.current_token.type == .TRUE) };
        const expression = ast.Expression{ .boolean = boolean };
        return try self.addExistingNode(ast.Expression, expression);
    }

    //grouped expression e.g an expresison starting with parenthesis
    fn parseGroupedExpression(self: *Parser) ParseErr!?u32 {
        self.nextToken();

        const expr = self.parseExpression(.LOWEST);
        if (!self.expectPeek(.RPAREN)) return null;

        return expr;
    }

    //if statements
    fn parseIfExpression(self: *Parser) ParseErr!?u32 {
        var if_expression = ast.IfExpression{
            .token = self.current_token,
            .condition = null,
            .consequence = undefined,
            .alternative = undefined,
        };

        if (!self.expectPeek(.LPAREN)) return null;

        self.nextToken();
        if_expression.condition = try self.parseExpression(.LOWEST);

        if (!self.expectPeek(.RPAREN)) return null;

        if (!self.expectPeek(.LBRACE)) return null;

        if_expression.consequence = try self.parseBlockStatement();
        if (self.peek_token.type == .ELSE) {
            self.nextToken();
            if (!self.expectPeek(.LBRACE)) return null;

            if_expression.alternative = try self.parseBlockStatement();
        }

        const expression = ast.Expression{ .if_expression = if_expression };
        return try self.addExistingNode(ast.Expression, expression);
    }

    //a group of statements contained in a block, e.g: everything between { ... }
    fn parseBlockStatement(self: *Parser) ParseErr!u32 {
        const index = try self.addNode(ast.BlockStatement);
        var block = self.getNode(index, ast.BlockStatement);

        block.token = self.current_token;
        block.statements = std.ArrayList(ast.Node).init(self.allocator);

        self.nextToken();
        while (self.current_token.type != .RBRACE and self.current_token.type != .EOF) : (self.nextToken()) {
            const statement_maybe = try self.parseStatement();
            if (statement_maybe) |statement| try block.statements.append(statement);
        }

        return index;
    }

    fn parseFunctionLiteral(self: *Parser) ParseErr!?u32 {
        var function_literal = ast.FunctionLiteral{
            .token = self.current_token,
            .parameters = undefined,
            .body = undefined,
        };

        if (!self.expectPeek(.LPAREN)) return null;

        const parems = try self.parseFunctionParameters();
        if (parems) |p| function_literal.parameters = p else return null;

        if (!self.expectPeek(.LBRACE)) return null;

        //create the expression and store it first, since parseBlockStatement may also create an expression
        //this is to ensure the ast Node for the function literal is always before the function parameters
        const expression = ast.Expression{ .function_literal = function_literal };
        const index = try self.addExistingNode(ast.Expression, expression);

        self.getNode(index, ast.Expression).function_literal.body = try self.parseBlockStatement();
        return index;
    }

    //parse function params, <func body>( param1, param2, ... paramN) { <blockexpression> }
    fn parseFunctionParameters(self: *Parser) ParseErr!?std.ArrayList(ast.Identifier) {
        var ret = std.ArrayList(ast.Identifier).init(self.allocator);

        if (self.peek_token.type == .RPAREN) {
            self.nextToken();
            return ret;
        }

        self.nextToken();
        var ident = ast.Identifier{ .token = self.current_token, .value = self.current_token.literal };
        try ret.append(ident);

        while (self.peek_token.type == .COMMA) {
            self.nextToken();
            self.nextToken();

            ident = ast.Identifier{ .token = self.current_token, .value = self.current_token.literal };
            try ret.append(ident);
        }

        if (!self.expectPeek(.RPAREN)) return null;

        return ret;
    }

    fn parseCallExpression(self: *Parser, left: ?u32) ParseErr!?u32 {
        const expr = ast.Expression{ .call_expression = .{ .token = self.current_token, .function = left.?, .arguments = try self.parseCallArguments() } };

        return try self.addExistingNode(ast.Expression, expr);
    }

    fn parseCallArguments(self: *Parser) ParseErr!std.ArrayList(u32) {
        var ret = std.ArrayList(u32).init(self.allocator);
        if (self.peek_token.type == .RPAREN) return ret;

        self.nextToken();
        var expr_maybe = try self.parseExpression(.LOWEST);
        if (expr_maybe) |e| try ret.append(e);

        while (self.peek_token.type == .COMMA) {
            self.nextToken();
            self.nextToken();

            expr_maybe = try self.parseExpression(.LOWEST);
            if (expr_maybe) |e| try ret.append(e);
        }

        if (!self.expectPeek(.RPAREN)) return std.ArrayList(u32).init(self.allocator);

        return ret;
    }
};

//Tests

test "let statement" {
    const input =
        \\let x = 5;
        \\let y = 10;
        \\let foobar = 838383;
    ;

    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();
    const program = parser.parseProgram();
    try std.testing.expectEqual(@as(usize, 3), program.statements.items.len);
    try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);

    const expected_ident = [_][]const u8{ "x", "y", "foobar" };
    const expected_nums = [_]i64{ 5, 10, 838383 };
    for (expected_ident, expected_nums, 0..) |ident, num, idx|
        try testLetStatementHelper(program.statements.items[idx], ident, num, &parser);
}

fn testLetStatementHelper(let: ast.Node, name: []const u8, num: i64, parser: *Parser) !void {
    const let_statement = parser.getNode(let.let_statement, ast.LetStatement);
    try std.testing.expectEqualSlices(u8, "let", let_statement.token.literal);

    const identifer = let_statement.name;
    try std.testing.expectEqualSlices(u8, name, identifer.value);

    const value = parser.getNode(let_statement.value, ast.Expression);
    const num_literal = value.integer_literal;
    try std.testing.expectEqual(num, num_literal.value);
}

test "return statement" {
    const input =
        \\return 5;
        \\return 10;
        \\return 9999;
    ;

    const expected_ident = [_]i64{ 5, 10, 9999 };

    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();

    const program = parser.parseProgram();
    try checkError(parser);
    try std.testing.expectEqual(@as(usize, 3), program.statements.items.len);
    for (program.statements.items, expected_ident) |statement, ident| {
        const return_statement = parser.getNode(statement.return_statement, ast.ReturnStatement);
        const return_expr = parser.getNode(return_statement.return_value, ast.Expression);
        try std.testing.expectEqualSlices(u8, "return", return_statement.token.literal);
        try std.testing.expectEqual(return_expr.integer_literal.value, ident);
    }
}

test "identifiers" {
    const input = "foobar;";
    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();

    const program = parser.parseProgram();
    try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    const expr = parser.getNode(program.statements.items[0].expression_statement, ast.ExpressionStatement);
    const ident = expr.expression.?.identifier;
    try std.testing.expectEqualSlices(u8, "foobar", ident.value);
    try std.testing.expectEqualSlices(u8, "foobar", ident.token.literal);
}

test "integer literal" {
    const input = "5;";
    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();

    const program = parser.parseProgram();
    try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    const expression_statement = program.statements.items[0].expression_statement;
    const integer = parser.getNode(expression_statement, ast.ExpressionStatement).expression.?.integer_literal;

    try std.testing.expectEqual(@as(i64, 5), integer.value);
    try std.testing.expectEqualSlices(u8, "5", integer.token.literal);
}

test "prefix operators" {
    const inputs = [_][]const u8{ "!5;", "-15;" };
    const expected_operators = [_][]const u8{ "!", "-" };
    const expected_vals = [_]i64{ 5, 15 };

    for (inputs, expected_operators, expected_vals) |input, expected_operator, expected_val| {
        var parser = Parser.init(input, std.testing.allocator);
        defer parser.deinit();

        const program = parser.parseProgram();
        try checkError(parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
        const expression_statement = program.statements.items[0].expression_statement;
        const prefix_expression = parser.getNode(expression_statement, ast.ExpressionStatement).expression.?.prefix_expression;

        try std.testing.expectEqualSlices(u8, expected_operator, prefix_expression.operator);
        const integer_index = prefix_expression.right;
        const integer = parser.getNode(integer_index.?, ast.Expression).integer_literal;
        try std.testing.expectEqual(@as(i64, expected_val), integer.value);
    }
}

//helper for tests, if there are any errors print them out to std err and return an error
fn checkError(parser: Parser) !void {
    for (parser.errors.items) |err| std.log.err("{s}\n", .{err});
    try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);
}

test "infix operators" {
    const inputs = [_][]const u8{ "5 + 5;", "5 - 5;", "5 * 5;", "5 / 5;", "5 > 5;", "5 < 5;", "5 == 5", "5 != 7" };
    const expected_lefts = [_]i64{ 5, 5, 5, 5, 5, 5, 5, 5 };
    const expected_operators = [_][]const u8{ "+", "-", "*", "/", ">", "<", "==", "!=" };
    const expected_rights = [_]i64{ 5, 5, 5, 5, 5, 5, 5, 7 };

    for (inputs, expected_lefts, expected_operators, expected_rights) |input, expected_left, expected_operator, expected_right| {
        var parser = Parser.init(input, std.testing.allocator);
        defer parser.deinit();

        const program = parser.parseProgram();
        try checkError(parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const expression_statement = parser.getNode(program.statements.items[0].expression_statement, ast.ExpressionStatement);
        const infix_expression = expression_statement.expression.?.infix_expression;

        var integer_index = infix_expression.left;
        var integer = parser.getNode(integer_index.?, ast.Expression).integer_literal;
        try std.testing.expectEqual(@as(i64, expected_left), integer.value);

        integer_index = infix_expression.right;
        integer = parser.getNode(integer_index.?, ast.Expression).integer_literal;
        try std.testing.expectEqual(@as(i64, expected_right), integer.value);

        try std.testing.expectEqualSlices(u8, expected_operator, infix_expression.operator);
    }
}

test "infix variables" {
    const input = "x + y";
    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();

    const program = parser.parseProgram();
    try checkError(parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
    const infix_expression = parser.getNode(program.statements.items[0].expression_statement, ast.ExpressionStatement);
    const infix = infix_expression.expression.?.infix_expression;
    try std.testing.expectEqualStrings("+", infix.operator);
    try std.testing.expectEqualStrings("x", parser.getNode(infix.left.?, ast.Expression).identifier.value);
    try std.testing.expectEqualStrings("y", parser.getNode(infix.right.?, ast.Expression).identifier.value);
}

test "boolean" {
    {
        const input = "false;";
        var parser = Parser.init(input, std.testing.allocator);
        defer parser.deinit();

        const program = parser.parseProgram();
        try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const expr = parser.getNode(program.statements.items[0].expression_statement, ast.ExpressionStatement);
        const ident = expr.expression.?.boolean;
        try std.testing.expectEqual(false, ident.value);
        try std.testing.expectEqualSlices(u8, "false", ident.token.literal);
    }
    {
        const input = "true;";
        var parser = Parser.init(input, std.testing.allocator);
        defer parser.deinit();

        const program = parser.parseProgram();
        try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const expr = parser.getNode(program.statements.items[0].expression_statement, ast.ExpressionStatement);
        const ident = expr.expression.?.boolean;
        try std.testing.expectEqual(true, ident.value);
        try std.testing.expectEqualSlices(u8, "true", ident.token.literal);
    }
}

test "group expressions" {
    const input = "1 + (2 + 3) + 4;";
    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();

    const program = parser.parseProgram();
    try checkError(parser);
    _ = program;
    try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);
}

test "if expression" {
    {
        const input = "if(x < y) { x }";
        var parser = Parser.init(input, std.testing.allocator);
        defer parser.deinit();

        const program = parser.parseProgram();
        try checkError(parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const statement = parser.getNode(program.statements.items[0].expression_statement, ast.ExpressionStatement);
        const if_statement = statement.expression.?.if_expression;
        const infix = parser.getNode(if_statement.condition.?, ast.Expression).infix_expression;
        _ = infix;
    }

    {
        const input = "if(x < y) { x } else { y }";
        var parser = Parser.init(input, std.testing.allocator);
        defer parser.deinit();

        const program = parser.parseProgram();
        try checkError(parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const statement = parser.getNode(program.statements.items[0].expression_statement, ast.ExpressionStatement);
        const if_statement = statement.expression.?.if_expression;
        const infix = parser.getNode(if_statement.condition.?, ast.Expression).infix_expression;
        _ = infix;
    }
}

test "function literal" {
    const input = "fn(x,y) { x + y; }";
    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();

    const program = parser.parseProgram();
    try checkError(parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    const expr = parser.getNode(program.statements.items[0].expression_statement, ast.Expression);
    const func_literal = expr.function_literal;
    try std.testing.expectEqual(@as(usize, 2), func_literal.parameters.items.len);
    try std.testing.expectEqualStrings("x", func_literal.parameters.items[0].value);
    try std.testing.expectEqualStrings("y", func_literal.parameters.items[1].value);

    const func_body = parser.getNode(func_literal.body, ast.BlockStatement);
    try std.testing.expectEqual(@as(usize, 1), func_body.statements.items.len);

    const statement = parser.getNode(func_body.statements.items[0].expression_statement, ast.ExpressionStatement);
    const body = statement.expression.?.infix_expression;

    try std.testing.expectEqualStrings("+", body.operator);
    try std.testing.expectEqualStrings("y", parser.getNode(body.right.?, ast.Expression).identifier.value);
    try std.testing.expectEqualStrings("x", parser.getNode(body.left.?, ast.Expression).identifier.value);
}

test "function params" {
    const inputs = [_][]const u8{ "fn() {};", "fn(x){}", "fn(x,y,z){}" };
    var p1 = std.ArrayList([]const u8).init(std.testing.allocator);
    defer p1.deinit();
    var p2 = std.ArrayList([]const u8).init(std.testing.allocator);
    defer p2.deinit();
    try p2.append("x");
    var p3 = std.ArrayList([]const u8).init(std.testing.allocator);
    defer p3.deinit();
    try p3.append("x");
    try p3.append("y");
    try p3.append("z");

    var params = std.ArrayList(std.ArrayList([]const u8)).init(std.testing.allocator);
    defer params.deinit();
    try params.append(p1);
    try params.append(p2);
    try params.append(p3);

    for (inputs, 0..) |input, idx| {
        var parser = Parser.init(input, std.testing.allocator);
        defer parser.deinit();

        const program = parser.parseProgram();

        const expr = parser.getNode(program.statements.items[0].expression_statement, ast.Expression);
        const func_literal = expr.function_literal;
        for (func_literal.parameters.items, 0..) |p, idx_2| {
            try std.testing.expectEqualStrings(params.items[idx].items[idx_2], p.value);
        }
    }
}

test "call expressions" {
    const input = "add(1,2*3, 4 + 5);";

    var parser = Parser.init(input, std.testing.allocator);
    defer parser.deinit();

    const program = parser.parseProgram();
    try checkError(parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
}
