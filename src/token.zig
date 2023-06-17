const std = @import("std");

pub const TokenType = enum {
    ILLEGAL,
    EOF,

    //identifiers + literals
    IDENT,
    INT,

    //operators
    ASSIGN,
    PLUS,
    MINUS,
    BANG,
    ASTERISK,
    SLASH,

    //less than, greater than
    LT,
    GT,

    //equal,not equal
    EQ,
    NOT_EQ,

    //delimiters
    COMMA,
    SEMICOLON,

    LPAREN,
    RPAREN,
    LBRACE,
    RBRACE,

    //keywords
    FUNCTION,
    LET,
    TRUE,
    FALSE,
    IF,
    ELSE,
    RETURN,
};

pub const Token = struct {
    type: TokenType,
    literal: []const u8,
};

const key_words = std.ComptimeStringMap(TokenType, .{
    .{ "fn", .FUNCTION },
    .{ "let", .LET },
    .{ "true", .TRUE },
    .{ "false", .FALSE },
    .{ "if", .IF },
    .{ "else", .ELSE },
    .{ "return", .RETURN },
});

pub fn lookupIdent(ident: []const u8) TokenType {
    return (key_words.get(ident)) orelse .IDENT;
}
