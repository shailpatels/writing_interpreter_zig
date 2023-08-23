const std = @import("std");

const Token = @import("token.zig").Token;
const Lexer = @import("lexer.zig").Lexer;

//root of the AST
pub const Program = struct {
    statements: std.ArrayList(Statement),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Program {
        return Program{ .statements = std.ArrayList(Statement).init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: *Program) void {
        for (self.statements.items) |s| {
            switch (s) {
                .let_statement => |l| {
                    self.allocator.destroy(l.name);
                    self.allocator.destroy(l);
                },
                .return_statement => |r| {
                    self.deinitExpression(r.return_value);
                    self.allocator.destroy(r);
                },
                .expression_statement => |e| {
                    if (e.expression) |expr| self.deinitExpression(expr);
                    self.allocator.destroy(e);
                },
            }
        }

        self.statements.deinit();
    }

    fn deinitExpression(self: *Program, e: *Expression) void {
        switch (e.*) {
            .prefix_expression => |p| {
                if (p.right) |expr| self.deinitExpression(expr);

                self.allocator.destroy(p);
            },
            .infix_expression => |i| {
                if (i.right) |expr| self.deinitExpression(expr);
                if (i.left) |expr| self.deinitExpression(expr);

                self.allocator.destroy(i);
            },
            inline else => |expr_t| self.allocator.destroy(expr_t),
        }

        self.allocator.destroy(e);
    }

    pub fn TokenLiteral(self: *const Program) []const u8 {
        return if (self.statements.items.len > 0) self.statements[0].TokenLiteral() else "";
    }
};

//get the token literal from a statement or expression
//type is expected to be of a tagged union
pub fn TokenLiteralHelper(comptime T: type, self: *const T) []const u8 {
    return switch (self.*) {
        inline else => |tag| tag.token.literal,
    };
}

pub const Statement = union(enum) {
    let_statement: *LetStatement,
    return_statement: *ReturnStatement,
    expression_statement: *ExpressionStatement,

    pub fn TokenLiteral(self: *const Statement) []const u8 {
        return TokenLiteralHelper(Statement, self);
    }

    //a statement can be a Let, Return
    pub const LetStatement = struct {
        token: Token,
        name: *Expression.Identifier,
        value: *Expression,
    };

    pub const ReturnStatement = struct {
        token: Token,
        return_value: *Expression,
    };

    pub const ExpressionStatement = struct {
        token: Token,
        expression: ?*Expression,
    };
};

pub const Expression = union(enum) {
    identifier: *Identifier,
    integer_literal: *IntegerLiteral,
    prefix_expression: *PrefixExpression,
    infix_expression: *InfixExpression,

    pub fn TokenLiteral(self: *const Expression) []const u8 {
        return TokenLiteralHelper(Expression, self);
    }

    //an expression can be an identifier, integer
    pub const Identifier = struct {
        token: Token,
        value: []const u8,
    };

    pub const IntegerLiteral = struct {
        token: Token,
        value: i64,
    };

    pub const PrefixExpression = struct {
        token: Token,
        operator: []const u8,
        right: ?*Expression,
    };

    pub const InfixExpression = struct {
        token: Token,
        left: ?*Expression,
        operator: []const u8,
        right: ?*Expression,
    };
};
