const std = @import("std");

const Token = @import("token.zig").Token;

pub const Lexer = struct {
    //input to lex
    input: []const u8,
    //current position in input
    position: u32 = 0,
    //current reading position in input (after current char)
    read_position: u32 = 0,
    //current char
    current_char: u8 = 0,

    //create a new lexer, nothing to deinit
    pub fn init(input: []const u8) Lexer {
        var ret = Lexer{ .input = input };
        ret.readChar();

        return ret;
    }

    //move the cursor forwards, if at end of input returns an EOF token
    pub fn nextToken(self: *Lexer) Token {
        self.skipWhiteSpace();

        const tok = switch (self.current_char) {
            '=' => blk: {
                if (self.peekChar() == '=') {
                    self.readChar();
                    break :blk Token{ .type = .EQ, .literal = "==" };
                } else {
                    break :blk Token{ .type = .ASSIGN, .literal = "=" };
                }
            },
            '+' => Token{ .type = .PLUS, .literal = "+" },
            '-' => Token{ .type = .MINUS, .literal = "-" },
            '!' => blk: {
                if (self.peekChar() == '=') {
                    self.readChar();
                    break :blk Token{ .type = .NOT_EQ, .literal = "!=" };
                } else {
                    break :blk Token{ .type = .BANG, .literal = "!" };
                }
            },
            '/' => Token{ .type = .SLASH, .literal = "/" },
            '*' => Token{ .type = .ASTERISK, .literal = "*" },
            '<' => Token{ .type = .LT, .literal = "<" },
            '>' => Token{ .type = .GT, .literal = ">" },
            ';' => Token{ .type = .SEMICOLON, .literal = ";" },
            '(' => Token{ .type = .LPAREN, .literal = "(" },
            ')' => Token{ .type = .RPAREN, .literal = ")" },
            ',' => Token{ .type = .COMMA, .literal = "," },
            '{' => Token{ .type = .LBRACE, .literal = "{" },
            '}' => Token{ .type = .RBRACE, .literal = "}" },

            else => {
                if (isLetter(self.current_char)) {
                    const lit = self.readIdentifier();
                    return Token{ .type = Token.TypeFromString(lit), .literal = lit };
                } else if (std.ascii.isDigit(self.current_char)) {
                    return Token{ .type = .INT, .literal = self.readNumber() };
                } else {
                    return Token{ .type = .EOF, .literal = "" };
                }
            },
        };

        self.readChar();
        return tok;
    }

    //end public interface

    fn readChar(self: *Lexer) void {
        self.current_char = if (self.read_position >= self.input.len) 0 else self.input[self.read_position];

        self.position = self.read_position;
        self.read_position += 1;
    }

    fn readIdentifier(self: *Lexer) []const u8 {
        const pos = self.position;
        while (isLetter(self.current_char)) : (self.readChar()) {}

        return self.input[pos..self.position];
    }

    fn readNumber(self: *Lexer) []const u8 {
        const pos = self.position;
        while (std.ascii.isDigit(self.current_char)) : (self.readChar()) {}

        return self.input[pos..self.position];
    }

    fn isLetter(c: u8) bool {
        return std.ascii.isAlphabetic(c) or c == '_';
    }

    //whitespace defined as spaces, tabs, newlines, carriage returns
    fn skipWhiteSpace(self: *Lexer) void {
        while (self.current_char == ' ' or self.current_char == '\t' or self.current_char == '\n' or self.current_char == '\r') : (self.readChar()) {}
    }

    fn peekChar(self: *Lexer) u8 {
        return if (self.read_position >= self.input.len) 0 else self.input[self.read_position];
    }
};

//tests

test "next token" {
    var lexer = Lexer.init("=+(){},;");

    const expected_types = [_]Token.Type{ .ASSIGN, .PLUS, .LPAREN, .RPAREN, .LBRACE, .RBRACE, .COMMA, .SEMICOLON, .EOF };
    const expected_literals = [_][]const u8{ "=", "+", "(", ")", "{", "}", ",", ";", "" };

    for (expected_types, expected_literals) |e_t, e_l| {
        const tok = lexer.nextToken();

        try std.testing.expectEqual(e_t, tok.type);
        try std.testing.expectEqualSlices(u8, e_l, tok.literal);
    }
}

test "next token 2" {
    const input =
        \\let five = 5;
        \\let ten = 10;
        \\
        \\let add = fn(x,y) {
        \\   x + y;
        \\};
        \\
        \\let result = add(five, ten);
    ;

    var lexer = Lexer.init(input);
    const expected_types = [_]Token.Type{ .LET, .IDENT, .ASSIGN, .INT, .SEMICOLON, .LET, .IDENT, .ASSIGN, .INT, .SEMICOLON, .LET, .IDENT, .ASSIGN, .FUNCTION, .LPAREN, .IDENT, .COMMA, .IDENT, .RPAREN, .LBRACE, .IDENT, .PLUS, .IDENT, .SEMICOLON, .RBRACE, .SEMICOLON, .LET, .IDENT, .ASSIGN, .IDENT, .LPAREN, .IDENT, .COMMA, .IDENT, .RPAREN, .SEMICOLON, .EOF };
    const expected_literals = [_][]const u8{ "let", "five", "=", "5", ";", "let", "ten", "=", "10", ";", "let", "add", "=", "fn", "(", "x", ",", "y", ")", "{", "x", "+", "y", ";", "}", ";", "let", "result", "=", "add", "(", "five", ",", "ten", ")", ";", "" };

    for (expected_types, expected_literals) |e_t, e_l| {
        const tok = lexer.nextToken();

        try std.testing.expectEqual(e_t, tok.type);
        try std.testing.expectEqualSlices(u8, e_l, tok.literal);
    }
}

test "next token 3" {
    const input =
        \\let five = 5;
        \\let ten = 10; 
        \\
        \\let add = fn(x,y) {
        \\   x + y;
        \\};
        \\
        \\let result = add(five,ten);
        \\!-/*5;
        \\5 < 10 > 5;
        \\
        \\if (5 < 10) {
        \\   return true;
        \\} else {
        \\   return false;
        \\}
        \\
        \\10 == 10;
        \\10 != 9;
    ;

    const expected_types = [_]Token.Type{ .LET, .IDENT, .ASSIGN, .INT, .SEMICOLON, .LET, .IDENT, .ASSIGN, .INT, .SEMICOLON, .LET, .IDENT, .ASSIGN, .FUNCTION, .LPAREN, .IDENT, .COMMA, .IDENT, .RPAREN, .LBRACE, .IDENT, .PLUS, .IDENT, .SEMICOLON, .RBRACE, .SEMICOLON, .LET, .IDENT, .ASSIGN, .IDENT, .LPAREN, .IDENT, .COMMA, .IDENT, .RPAREN, .SEMICOLON, .BANG, .MINUS, .SLASH, .ASTERISK, .INT, .SEMICOLON, .INT, .LT, .INT, .GT, .INT, .SEMICOLON, .IF, .LPAREN, .INT, .LT, .INT, .RPAREN, .LBRACE, .RETURN, .TRUE, .SEMICOLON, .RBRACE, .ELSE, .LBRACE, .RETURN, .FALSE, .SEMICOLON, .RBRACE, .INT, .EQ, .INT, .SEMICOLON, .INT, .NOT_EQ, .INT, .SEMICOLON, .EOF };
    const expected_literals = [_][]const u8{ "let", "five", "=", "5", ";", "let", "ten", "=", "10", ";", "let", "add", "=", "fn", "(", "x", ",", "y", ")", "{", "x", "+", "y", ";", "}", ";", "let", "result", "=", "add", "(", "five", ",", "ten", ")", ";", "!", "-", "/", "*", "5", ";", "5", "<", "10", ">", "5", ";", "if", "(", "5", "<", "10", ")", "{", "return", "true", ";", "}", "else", "{", "return", "false", ";", "}", "10", "==", "10", ";", "10", "!=", "9", ";", "" };

    var lexer = Lexer.init(input);
    for (expected_types, expected_literals) |e_t, e_l| {
        const tok = lexer.nextToken();

        try std.testing.expectEqual(e_t, tok.type);
        try std.testing.expectEqualSlices(u8, e_l, tok.literal);
    }
}

test "function" {
    const input = "fn(x,y) { x + y; }";
    var lexer = Lexer.init(input);

    const expected_types = [_]Token.Type{ .FUNCTION, .LPAREN, .IDENT, .COMMA, .IDENT, .RPAREN, .LBRACE, .IDENT, .PLUS, .IDENT, .SEMICOLON, .RBRACE };
    for (expected_types) |e_t| {
        const tok = lexer.nextToken();
        try std.testing.expectEqual(e_t, tok.type);
    }
}
