const std = @import("std");

const Lexer = @import("lexer.zig").Lexer;
const Token = @import("token.zig").Token;
const ast = @import("ast.zig");

pub const Parser = struct {
    const Precedence = enum {
        LOWEST,
        EQUALS, // ==
        LESSGREATER, // > or <
        SUM, // +
        PRODUCT, // *
        PREFIX, // -X or !X
        CALL, // fn(X)
    };

    //fn definitions for parsing specific expressions
    const prefix_fn = *const (fn (*Parser) error{OutOfMemory}!?ast.Expression);
    const infix_fn = *const (fn (*Parser, ?ast.Expression) error{OutOfMemory}!?ast.Expression);

    precedences: std.AutoHashMap(Token.Type, Precedence),

    lexer: Lexer,

    //store a 'cursor' to the current token being parsed and the very next one
    current_token: Token = undefined,
    peek_token: Token = undefined,
    program: ast.Program = undefined,

    errors: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    //lookup tables to get a specific function callback given a token type
    prefix_parse_map: std.AutoHashMap(Token.Type, prefix_fn),
    infix_parse_map: std.AutoHashMap(Token.Type, infix_fn),

    pub fn init(allocator: std.mem.Allocator, lexer: Lexer) Parser {
        var p = Parser{
            .lexer = lexer,
            .errors = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
            .prefix_parse_map = std.AutoHashMap(Token.Type, prefix_fn).init(allocator),
            .infix_parse_map = std.AutoHashMap(Token.Type, infix_fn).init(allocator),
            .precedences = std.AutoHashMap(Token.Type, Precedence).init(allocator),
        };

        p.nextToken();
        p.nextToken();

        const keys = [_]Token.Type{ .LPAREN, .EQ, .NOT_EQ, .LT, .GT, .PLUS, .MINUS, .SLASH, .ASTERISK };
        const vals = [_]Precedence{ .CALL, .EQUALS, .EQUALS, .LESSGREATER, .LESSGREATER, .SUM, .SUM, .PRODUCT, .PRODUCT };
        p.precedences.ensureTotalCapacity(keys.len) catch |err| {
            std.debug.print("Failed to create precedence table{!}\n", .{err});
            return p;
        };

        //future: could build these lookup tables statically
        inline for (keys, vals) |key, val| p.precedences.putAssumeCapacity(key, val);
        p.prefix_parse_map.ensureTotalCapacity(9) catch |err| {
            std.debug.print("Failed to register prefix callbacks: {!}\n", .{err});
            return p;
        };

        p.prefix_parse_map.putAssumeCapacity(.IDENT, Parser.parseIdentifier);
        p.prefix_parse_map.putAssumeCapacity(.INT, Parser.parseIntegerLiteral);
        p.prefix_parse_map.putAssumeCapacity(.BANG, Parser.parsePrefixExpression);
        p.prefix_parse_map.putAssumeCapacity(.MINUS, Parser.parsePrefixExpression);
        p.prefix_parse_map.putAssumeCapacity(.TRUE, Parser.parseBoolean);
        p.prefix_parse_map.putAssumeCapacity(.FALSE, Parser.parseBoolean);
        p.prefix_parse_map.putAssumeCapacity(.LPAREN, Parser.parseGroupedExpression);
        p.prefix_parse_map.putAssumeCapacity(.IF, Parser.parseIfExpression);
        p.prefix_parse_map.putAssumeCapacity(.FUNCTION, Parser.parseFunctionLiteral);

        p.infix_parse_map.ensureTotalCapacity(9) catch |err| {
            std.debug.print("Failed to register infix callbacks: {!}\n", .{err});
            return p;
        };

        p.infix_parse_map.putAssumeCapacity(.PLUS, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.MINUS, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.SLASH, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.ASTERISK, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.EQ, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.NOT_EQ, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.LT, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.GT, Parser.parseInfixExpression);
        p.infix_parse_map.putAssumeCapacity(.LPAREN, Parser.parseCallExpression);

        return p;
    }

    pub fn deinit(self: *Parser) void {
        defer self.program.deinit();

        for (self.errors.items) |err| {
            self.allocator.free(err);
        }
        self.errors.deinit();
        self.prefix_parse_map.deinit();
        self.infix_parse_map.deinit();
        self.precedences.deinit();
    }

    pub fn parseProgram(self: *Parser) ast.Program {
        self.program = ast.Program.init(self.allocator);
        while (self.current_token.type != .EOF) {
            const statement = self.parseStatement();
            if (statement) |stat| {
                if (stat) |s| {
                    self.program.statements.append(s) catch |err| {
                        std.debug.print("Failed to append to ArrayList: {any}\n", .{err});
                        return self.program;
                    };
                }
            } else |err| {
                std.debug.print("Failed to parse statement: {any}\n", .{err});
                return self.program;
            }

            self.nextToken();
        }

        return self.program;
    }

    fn nextToken(self: *Parser) void {
        self.current_token = self.peek_token;
        self.peek_token = self.lexer.nextToken();
    }

    fn parseStatement(self: *Parser) error{OutOfMemory}!?ast.Statement {
        return switch (self.current_token.type) {
            .LET => try self.parseLetStatement(),
            .RETURN => try self.parseReturnStatement(),
            else => try self.parseExpressionStatement(),
        };
    }

    fn parseLetStatement(self: *Parser) error{OutOfMemory}!?ast.Statement {
        var statement = ast.Statement{ .let_statement = try self.allocator.create(ast.Statement.LetStatement) };
        var let_statement = statement.let_statement;
        let_statement.token = self.current_token;

        if (!self.expectPeek(.IDENT)) {
            self.allocator.destroy(let_statement);
            return null;
        }

        let_statement.name = try self.allocator.create(ast.Expression.Identifier);
        let_statement.name.token = self.current_token;
        let_statement.name.value = self.current_token.literal;

        if (!self.expectPeek(.ASSIGN)) {
            self.allocator.destroy(let_statement.name);
            self.allocator.destroy(let_statement);
            return null;
        }

        self.nextToken();
        const val_maybe = try self.parseExpression(.LOWEST);
        if (val_maybe) |val| {
            const expr = try self.allocator.create(ast.Expression);
            expr.* = val;
            let_statement.value = expr;
        } else {
            let_statement.value = null;
        }

        if (self.peek_token.type == .SEMICOLON) self.nextToken();

        return statement;
    }

    fn parseReturnStatement(self: *Parser) error{OutOfMemory}!?ast.Statement {
        var statement = ast.Statement{ .return_statement = try self.allocator.create(ast.Statement.ReturnStatement) };
        var return_statement = statement.return_statement;

        return_statement.token = self.current_token;
        self.nextToken();

        const return_expr = try self.parseExpression(.LOWEST);
        if (return_expr) |ret| {
            const expr = try self.allocator.create(ast.Expression);
            expr.* = ret;
            return_statement.return_value = expr;
        } else {
            return_statement.return_value = null;
        }

        //todo skipping expressions
        while (self.current_token.type != .SEMICOLON) : (self.nextToken()) {}
        return statement;
    }

    fn parseExpressionStatement(self: *Parser) error{OutOfMemory}!?ast.Statement {
        var statement = ast.Statement{ .expression_statement = try self.allocator.create(ast.Statement.ExpressionStatement) };

        //allocate the expression parsed off the stack
        const expr_local_maybe = try self.parseExpression(.LOWEST);

        if (expr_local_maybe) |expr_local| {
            const expr = try self.allocator.create(ast.Expression);
            expr.* = expr_local;
            statement.expression_statement.expression = expr;
        } else {
            statement.expression_statement.expression = null;
        }

        if (self.peek_token.type == .SEMICOLON) self.nextToken();

        return statement;
    }

    fn parseExpression(self: *Parser, precedence: Precedence) error{OutOfMemory}!?ast.Expression {
        const prefix_maybe = self.prefix_parse_map.get(self.current_token.type);
        if (prefix_maybe == null) {
            try self.noPrefixParseError(self.current_token.type);
            return null;
        }

        const prefix = prefix_maybe.?;
        var left_expr = try prefix(self);

        while (self.peek_token.type != .SEMICOLON and @intFromEnum(precedence) < @intFromEnum(self.peekPrecedence())) {
            const infix_maybe = self.infix_parse_map.get(self.peek_token.type);
            if (infix_maybe == null) {
                return left_expr;
            }

            self.nextToken();

            const infix = infix_maybe.?;
            left_expr = try infix(self, left_expr);
        }

        return left_expr;
    }

    fn parseIdentifier(self: *Parser) error{OutOfMemory}!?ast.Expression {
        var identifier_expression = ast.Expression{ .identifier = try self.allocator.create(ast.Expression.Identifier) };
        var identifier = identifier_expression.identifier;

        identifier.token = self.current_token;
        identifier.value = self.current_token.literal;
        return identifier_expression;
    }

    fn parseIntegerLiteral(self: *Parser) error{OutOfMemory}!?ast.Expression {
        const val = std.fmt.parseInt(i64, self.current_token.literal, 10) catch |err| {
            const str = std.fmt.allocPrint(self.allocator, "failed to parse '{s}' to an integer: {!}", .{ self.current_token.literal, err }) catch "failed to parse integer";
            try self.errors.append(str);
            return null;
        };

        var integer_expression = ast.Expression{ .integer_literal = try self.allocator.create(ast.Expression.IntegerLiteral) };
        var integer_literal = integer_expression.integer_literal;

        integer_literal.token = self.current_token;
        integer_literal.value = val;
        return integer_expression;
    }

    fn parsePrefixExpression(self: *Parser) error{OutOfMemory}!?ast.Expression {
        var expression = ast.Expression{ .prefix_expression = try self.allocator.create(ast.Expression.PrefixExpression) };
        var prefix = expression.prefix_expression;

        prefix.token = self.current_token;
        prefix.operator = self.current_token.literal;

        self.nextToken();

        //allocate the parsed expression off the stack
        var prefix_expr_maybe = try self.parseExpression(.PREFIX);
        if (prefix_expr_maybe) |prefix_expr| {
            const expr = try self.allocator.create(ast.Expression);
            expr.* = prefix_expr;
            prefix.right = expr;
        } else {
            prefix.right = null;
        }

        return expression;
    }

    fn parseInfixExpression(self: *Parser, left_maybe: ?ast.Expression) error{OutOfMemory}!?ast.Expression {
        var expression = ast.Expression{ .infix_expression = try self.allocator.create(ast.Expression.InfixExpression) };
        var infix = expression.infix_expression;
        infix.token = self.current_token;
        infix.operator = self.current_token.literal;

        if (left_maybe) |left| {
            const expr = try self.allocator.create(ast.Expression);
            expr.* = left;
            infix.left = expr;
        } else {
            infix.left = null;
        }

        const cur_prec = self.currPrecedence();
        self.nextToken();
        var right_expr_maybe = try self.parseExpression(cur_prec);
        if (right_expr_maybe) |right_expr| {
            const expr = try self.allocator.create(ast.Expression);
            expr.* = right_expr;
            infix.right = expr;
        } else {
            infix.right = null;
        }

        return expression;
    }

    fn parseCallExpression(self: *Parser, function: ?ast.Expression) error{OutOfMemory}!?ast.Expression {
        const expr = ast.Expression{ .call_expression = try self.allocator.create(ast.Expression.CallExpression) };
        const call = expr.call_expression;
        call.token = self.current_token;
        call.function = function;

        const result = try self.parseCallArguments(&call.arguments);
        if (!result) {
            call.arguments.clearAndFree();
        }

        return expr;
    }

    fn parseCallArguments(self: *Parser, args: *std.ArrayList(ast.Expression)) error{OutOfMemory}!bool {
        args.* = std.ArrayList(ast.Expression).init(self.allocator);

        if (self.peek_token.type == .RPAREN) {
            self.nextToken();
            return true;
        }

        self.nextToken();
        const expr_maybe = try self.parseExpression(.LOWEST);
        if (expr_maybe) |expr| {
            try args.append(expr);
        }

        while (self.peek_token.type == .COMMA) {
            self.nextToken();
            self.nextToken();

            const expr_maybe_next = try self.parseExpression(.LOWEST);
            if (expr_maybe_next) |expr| {
                try args.append(expr);
            }
        }

        if (!self.expectPeek(.RPAREN)) return false;

        return true;
    }

    fn parseBoolean(self: *Parser) error{OutOfMemory}!?ast.Expression {
        var expression = ast.Expression{ .boolean = try self.allocator.create(ast.Expression.Boolean) };
        expression.boolean.token = self.current_token;
        expression.boolean.value = self.current_token.type == .TRUE;
        return expression;
    }

    fn parseGroupedExpression(self: *Parser) error{OutOfMemory}!?ast.Expression {
        self.nextToken();

        const exp = self.parseExpression(.LOWEST);
        if (self.peek_token.type != .RPAREN) return null;

        return exp;
    }

    fn parseIfExpression(self: *Parser) error{OutOfMemory}!?ast.Expression {
        var expression = ast.Expression{ .if_expression = try self.allocator.create(ast.Expression.IfExpression) };
        var if_expression = expression.if_expression;
        if_expression.token = self.current_token;

        if (!self.expectPeek(.LPAREN)) return null;

        self.nextToken();

        var expr_maybe = try self.parseExpression(.LOWEST);
        if (expr_maybe) |expr_local| {
            const expr = try self.allocator.create(ast.Expression);
            expr.* = expr_local;
            if_expression.condition = expr;
        } else {
            if_expression.condition = null;
        }

        if (!self.expectPeek(.RPAREN)) return null;

        if (!self.expectPeek(.LBRACE)) return null;

        var block_local = try self.parseBlockStatement();
        const block = try self.allocator.create(ast.Statement.BlockStatement);
        block.* = block_local;
        if_expression.consequence = block;
        if_expression.alternative = null;

        if (self.peek_token.type == .ELSE) {
            self.nextToken();

            if (!self.expectPeek(.LBRACE)) {
                return null;
            }

            var alt_local = try self.parseBlockStatement();
            const alt = try self.allocator.create(ast.Statement.BlockStatement);
            alt.* = alt_local;

            if_expression.alternative = alt;
        }

        return expression;
    }

    fn parseFunctionLiteral(self: *Parser) error{OutOfMemory}!?ast.Expression {
        const exp = ast.Expression{ .function_literal = try self.allocator.create(ast.Expression.FunctionLiteral) };
        const function = exp.function_literal;
        function.token = self.current_token;

        if (!self.expectPeek(.LPAREN)) return null;

        const result = try self.parseFunctionParameters(&function.parameters);
        if (result == null) function.parameters.clearAndFree();

        if (!self.expectPeek(.LBRACE)) return null;

        function.body = try self.allocator.create(ast.Statement.BlockStatement);
        function.body.* = try self.parseBlockStatement();

        return exp;
    }

    fn parseFunctionParameters(self: *Parser, params: *std.ArrayList(ast.Expression.Identifier)) error{OutOfMemory}!?bool {
        params.* = std.ArrayList(ast.Expression.Identifier).init(self.allocator);

        if (self.peek_token.type == .RPAREN) {
            self.nextToken();
            return true;
        }

        self.nextToken();
        var ident = ast.Expression.Identifier{ .token = self.current_token, .value = self.current_token.literal };
        try params.append(ident);

        while (self.peek_token.type == .COMMA) {
            self.nextToken();
            self.nextToken();

            ident = ast.Expression.Identifier{ .token = self.current_token, .value = self.current_token.literal };
            try params.append(ident);
        }

        return if (!self.expectPeek(.RPAREN)) null else true;
    }

    fn parseBlockStatement(self: *Parser) error{OutOfMemory}!ast.Statement.BlockStatement {
        var statement = ast.Statement.BlockStatement{ .token = self.current_token, .statements = std.ArrayList(ast.Statement).init(self.allocator) };

        self.nextToken();
        while (self.current_token.type != .RBRACE and self.current_token.type != .EOF) {
            var stat = try self.parseStatement();
            if (stat) |s| {
                try statement.statements.append(s);
            }
            self.nextToken();
        }

        return statement;
    }

    fn noPrefixParseError(self: *Parser, t: Token.Type) error{OutOfMemory}!void {
        const str = try std.fmt.allocPrint(self.allocator, "no prefix parse function for {s}", .{@tagName(t)});
        try self.errors.append(str);
    }

    fn peekPrecedence(self: *const Parser) Precedence {
        if (self.precedences.get(self.peek_token.type)) |prec| {
            return prec;
        } else {
            return .LOWEST;
        }
    }

    fn currPrecedence(self: *const Parser) Precedence {
        if (self.precedences.get(self.current_token.type)) |prec| {
            return prec;
        } else {
            return .LOWEST;
        }
    }

    fn expectPeek(self: *Parser, expected: Token.Type) bool {
        if (expected == self.peek_token.type) {
            self.nextToken();
            return true;
        }

        self.peekError(expected);
        return false;
    }

    fn peekError(self: *Parser, expected: Token.Type) void {
        var msg = std.fmt.allocPrint(self.allocator, "expected token of '{s}', got '{s}' instead", .{ @tagName(expected), @tagName(self.peek_token.type) }) catch "Failed to format err string";
        self.errors.append(msg) catch |err| {
            std.debug.print("Failed to append to errors list: {any}", .{err});
        };
    }
};

///////////
//Testing//
///////////

test "let statements" {
    const input =
        \\let x = 5;
        \\let y = 10;
        \\let foobar = 838383;
    ;

    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();

    try checkParseError(&parser);
    try std.testing.expectEqual(@as(usize, 3), program.statements.items.len);
    const expected = [_][]const u8{ "x", "y", "foobar" };
    const expected_vals = [_]i64{ 5, 10, 838383 };
    for (expected, expected_vals, 0..) |ident, expected_val, i| {
        const actual = program.statements.items[i];

        try std.testing.expectEqualSlices(u8, "let", actual.TokenLiteral());
        try std.testing.expectEqualSlices(u8, ident, actual.let_statement.name.value);
        try std.testing.expectEqualSlices(u8, ident, actual.let_statement.name.token.literal);

        const val = actual.let_statement.value.?.integer_literal.value;
        try std.testing.expectEqual(expected_val, val);
    }
}

test "return statements" {
    const input =
        \\return 5;
        \\return 10;
        \\return 993322;
    ;

    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();
    try checkParseError(&parser);

    try std.testing.expectEqual(@as(usize, 3), program.statements.items.len);
    for (program.statements.items) |statement| {
        try std.testing.expectEqualSlices(u8, "return", statement.TokenLiteral());
    }
}

fn checkParseError(parser: *Parser) error{ParseErrors}!void {
    if (parser.errors.items.len == 0) {
        return;
    }

    std.log.err("Parser had {d} errors\n", .{parser.errors.items.len});
    for (parser.errors.items) |msg| {
        std.log.err("{s}", .{msg});
    }

    return error.ParseErrors;
}

test "identifier expression" {
    const input = "foobar;";

    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();

    try checkParseError(&parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
    var expression = program.statements.items[0].expression_statement.expression;
    var identifier = expression.?.identifier;
    try std.testing.expectEqualSlices(u8, "foobar", identifier.value);
    try std.testing.expectEqualSlices(u8, "foobar", identifier.token.literal);
}

test "integer literal expression" {
    const input = "5;";

    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();

    try checkParseError(&parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
    var statement = program.statements.items[0].expression_statement.expression.?.integer_literal;

    try std.testing.expectEqual(@as(i64, 5), statement.value);
    try std.testing.expectEqualSlices(u8, "5", statement.token.literal);
}

test "parse prefix expression" {
    const inputs = [_][]const u8{ "!5;", "-15;" };
    const operators = [_][]const u8{ "!", "-" };
    const integers = [_]i64{ 5, 15 };

    inline for (inputs, operators, integers) |input, operator, integer| {
        var lexer = Lexer.init(input);
        var parser = Parser.init(std.testing.allocator, lexer);
        defer parser.deinit();

        var program = parser.parseProgram();

        try checkParseError(&parser);

        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const statement = program.statements.items[0].expression_statement.expression.?.prefix_expression;
        try std.testing.expectEqualSlices(u8, operator, statement.operator);

        const int = statement.right.?.integer_literal;
        try std.testing.expectEqual(integer, int.value);
        try std.testing.expectEqualSlices(u8, std.fmt.comptimePrint("{d}", .{integer}), int.token.literal);
    }
}

test "parse infix expression" {
    const inputs = [_][]const u8{ "5 + 5;", "5 - 5;", "5 * 5;", "5 / 5;", "5 > 5;", "5 < 5;", "5 == 5;", "5 != 5;" };
    const left_vals = [_]i64{ 5, 5, 5, 5, 5, 5, 5, 5 };
    const operators = [_][]const u8{ "+", "-", "*", "/", ">", "<", "==", "!=" };
    const right_vals = [_]i64{ 5, 5, 5, 5, 5, 5, 5, 5 };

    inline for (inputs, left_vals, operators, right_vals) |input, left_val, operator, right_val| {
        var lexer = Lexer.init(input);
        var parser = Parser.init(std.testing.allocator, lexer);
        defer parser.deinit();

        var program = parser.parseProgram();

        try checkParseError(&parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const infix = program.statements.items[0].expression_statement.expression.?.infix_expression;
        //left expr
        try std.testing.expectEqual(left_val, infix.left.?.integer_literal.value);
        try std.testing.expectEqualSlices(u8, std.fmt.comptimePrint("{d}", .{left_val}), infix.left.?.integer_literal.token.literal);
        try std.testing.expectEqualSlices(u8, operator, infix.operator);

        //right expr
        try std.testing.expectEqual(right_val, infix.right.?.integer_literal.value);
        try std.testing.expectEqualSlices(u8, std.fmt.comptimePrint("{d}", .{right_val}), infix.right.?.integer_literal.token.literal);
    }
}

test "boolean expressions" {
    const inputs = [_][]const u8{ "true;", "false;" };
    const expected_vals = [_]bool{ true, false };

    for (inputs, expected_vals) |input, expected| {
        var lexer = Lexer.init(input);
        var parser = Parser.init(std.testing.allocator, lexer);
        defer parser.deinit();

        var program = parser.parseProgram();

        try checkParseError(&parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const boolean = program.statements.items[0].expression_statement.expression.?.boolean;
        try std.testing.expectEqual(expected, boolean.value);
    }
}

test "boolean values" {
    const inputs = [_][]const u8{ "true == true", "true != false", "false == false" };
    const lefts = [_]bool{ true, true, false };
    const operators = [_][]const u8{ "==", "!=", "==" };
    const rights = [_]bool{ true, false, false };

    for (inputs, lefts, operators, rights) |input, left, operator, right| {
        var lexer = Lexer.init(input);
        var parser = Parser.init(std.testing.allocator, lexer);
        defer parser.deinit();

        var program = parser.parseProgram();

        try checkParseError(&parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const infix = program.statements.items[0].expression_statement.expression.?.infix_expression;
        try std.testing.expectEqual(left, infix.left.?.boolean.value);
        try std.testing.expectEqual(right, infix.right.?.boolean.value);
        try std.testing.expectEqual(operator, infix.operator);
    }
}

test "if expression" {
    const input = "if (x < y) { x }";
    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();

    try checkParseError(&parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    const statement = program.statements.items[0].expression_statement;
    const if_expr = statement.expression.?.if_expression;

    const infix = if_expr.condition.?.infix_expression;

    try std.testing.expect(std.mem.eql(u8, "x", infix.left.?.identifier.value));
    try std.testing.expect(std.mem.eql(u8, "<", infix.operator));
    try std.testing.expect(std.mem.eql(u8, "y", infix.right.?.identifier.value));

    try std.testing.expectEqual(@as(usize, 1), if_expr.consequence.statements.items.len);
    const consequence = if_expr.consequence.statements.items[0].expression_statement;

    try std.testing.expect(std.mem.eql(u8, "x", consequence.expression.?.identifier.value));
    try std.testing.expect(null == if_expr.alternative);
}

test "if else expression" {
    const input = "if (x < y) { x } else { y }";
    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();

    try checkParseError(&parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    const statement = program.statements.items[0].expression_statement;
    const if_expr = statement.expression.?.if_expression;

    const infix = if_expr.condition.?.infix_expression;

    try std.testing.expect(std.mem.eql(u8, "x", infix.left.?.identifier.value));
    try std.testing.expect(std.mem.eql(u8, "<", infix.operator));
    try std.testing.expect(std.mem.eql(u8, "y", infix.right.?.identifier.value));

    try std.testing.expectEqual(@as(usize, 1), if_expr.consequence.statements.items.len);
    const consequence = if_expr.consequence.statements.items[0].expression_statement;

    try std.testing.expect(std.mem.eql(u8, "x", consequence.expression.?.identifier.value));

    try std.testing.expectEqual(@as(usize, 1), if_expr.alternative.?.statements.items.len);
    const alternative = if_expr.alternative.?.statements.items[0].expression_statement;
    try std.testing.expect(std.mem.eql(u8, "y", alternative.expression.?.identifier.value));
}

test "function literal" {
    const input = "fn(x,y){ x + y }";

    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();
    try checkParseError(&parser);
    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    const function = program.statements.items[0].expression_statement.expression.?.function_literal;
    try std.testing.expectEqual(@as(usize, 2), function.parameters.items.len);

    try std.testing.expect(std.mem.eql(u8, "x", function.parameters.items[0].value));
    try std.testing.expect(std.mem.eql(u8, "y", function.parameters.items[1].value));

    try std.testing.expectEqual(@as(usize, 1), function.body.statements.items.len);
    const infix_body = function.body.statements.items[0].expression_statement.expression.?.infix_expression;

    try std.testing.expect(std.mem.eql(u8, "x", infix_body.left.?.identifier.value));
    try std.testing.expect(std.mem.eql(u8, "+", infix_body.operator));
    try std.testing.expect(std.mem.eql(u8, "y", infix_body.right.?.identifier.value));
}

test "function parameter parsing" {
    {
        const input = "fn(){}";
        var lexer = Lexer.init(input);
        var parser = Parser.init(std.testing.allocator, lexer);
        defer parser.deinit();

        var program = parser.parseProgram();
        try checkParseError(&parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
        const function = program.statements.items[0].expression_statement.expression.?.function_literal;
        try std.testing.expectEqual(@as(usize, 0), function.parameters.items.len);
    }

    {
        const input = "fn(x){}";
        var lexer = Lexer.init(input);
        var parser = Parser.init(std.testing.allocator, lexer);
        defer parser.deinit();

        var program = parser.parseProgram();
        try checkParseError(&parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
        const function = program.statements.items[0].expression_statement.expression.?.function_literal;
        try std.testing.expectEqual(@as(usize, 1), function.parameters.items.len);
    }

    {
        const input = "fn(x,y,z){}";
        var lexer = Lexer.init(input);
        var parser = Parser.init(std.testing.allocator, lexer);
        defer parser.deinit();

        var program = parser.parseProgram();
        try checkParseError(&parser);
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
        const function = program.statements.items[0].expression_statement.expression.?.function_literal;
        try std.testing.expectEqual(@as(usize, 3), function.parameters.items.len);
    }
}

test "call expression" {
    const input = "add(1, 2 * 3, 4 + 5)";
    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = parser.parseProgram();
    try checkParseError(&parser);

    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);
    const call_expr = program.statements.items[0].expression_statement.expression.?.call_expression;
    const identifer = call_expr.function.?.identifier;
    try std.testing.expect(std.mem.eql(u8, "add", identifer.value));
    try std.testing.expectEqual(@as(usize, 3), call_expr.arguments.items.len);
}
