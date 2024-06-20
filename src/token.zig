const std = @import("std");

pub const Token = struct {
    type: Type,
    literal: []const u8,

    pub const Type = enum {
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

    const key_words = std.StaticStringMap(Token.Type).initComptime(.{
        .{ "fn", .FUNCTION },
        .{ "let", .LET },
        .{ "true", .TRUE },
        .{ "false", .FALSE },
        .{ "if", .IF },
        .{ "else", .ELSE },
        .{ "return", .RETURN },
    });

    pub fn TypeFromString(ident: []const u8) Type {
        return (key_words.get(ident)) orelse .IDENT;
    }
};
