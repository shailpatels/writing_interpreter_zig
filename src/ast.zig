const std = @import("std");

const Token = @import("token.zig").Token;
const Lexer = @import("lexer.zig").Lexer;

///AST representation

//the program node is the root of the AST
pub const Program = struct {
    statements: std.ArrayList(Node),

    pub fn init(allocator: std.mem.Allocator) Program {
        return Program{ .statements = std.ArrayList(Node).init(allocator) };
    }

    pub fn deinit(self: *Program) void {
        self.statements.deinit();
    }
};

//an individual node in an AST
pub const Node = union(enum) {
    //possible nodes, each is an index to the struct in memory
    let_statement: u32,
    return_statement: u32,
    identifier: u32,
    expression_statement: u32,
};

//union to cover possible expressions
pub const Expression = union(enum) {
    identifier: Identifier,
    integer_literal: IntegerLiteral,
    prefix_expression: PrefixExpression,
    infix_expression: InfixExpression,
    boolean: Boolean,
    if_expression: IfExpression,
    function_literal: FunctionLiteral,
    call_expression: CallExpression,
};

//definitions of possible nodes and expression

//a let statement, "let <name> = <value>;"
pub const LetStatement = struct {
    token: Token,
    name: Identifier, //index to an identifier
    value: u32, //index to an expression
};

//a return statement, "return <return_value>;"
pub const ReturnStatement = struct {
    token: Token,
    return_value: u32, //index to an expression
};

//an identifier, "<identifier>"
//e.g a variable name
pub const Identifier = struct {
    token: Token,
    value: []const u8,
};

//an expression statement is a single line that is also an expression
//e.g: 5+5
pub const ExpressionStatement = struct {
    token: Token,
    expression: ?Expression,
};

//represents an integner, e.g.: 5;
pub const IntegerLiteral = struct {
    token: Token,
    value: i64,
};

pub const PrefixExpression = struct {
    token: Token,
    operator: []const u8,
    right: ?u32, //index to an expression
};

pub const InfixExpression = struct {
    token: Token,
    left: ?u32, //index to an expression
    operator: []const u8,
    right: ?u32, //index to an expression
};

pub const Boolean = struct {
    token: Token,
    value: bool,
};

pub const IfExpression = struct {
    token: Token,
    condition: ?u32, //index to an expression
    consequence: u32, //index to a block statement
    alternative: u32, //index to a block statement
};

pub const BlockStatement = struct {
    token: Token,
    statements: std.ArrayList(Node),
};

pub const FunctionLiteral = struct {
    token: Token,
    parameters: std.ArrayList(Identifier),
    body: u32, //index to a block statement
};

pub const CallExpression = struct {
    token: Token,
    function: u32, //index to an expression
    arguments: std.ArrayList(u32), //indexes to expressions
};
