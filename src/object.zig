const std = @import("std");

pub const ObjectType = enum {
    INTEGER_OBJ,
    BOOLEAN_OBJ,
};

pub fn Type(obj: anytype) ObjectType {
    return switch (@TypeOf(obj)) {
        Integer => .INTEGER_OBJ,
        Boolean => .BOOLEAN_OBJ,
        Null => .NULL_OBJ,
    };
}

pub const Object = union {
    integer: Integer,
    boolean: Boolean,
    null: Null,
};

pub const Integer = struct {
    value: i64,

    pub fn Inspect(self: *const Integer, allocator: std.mem.Allocator) []const u8 {
        return std.fmt.allocPrint(allocator, "%d", .{self.value});
    }
};

pub const Boolean = struct {
    value: bool,

    pub fn Inspect(self: *const Integer, allocator: std.mem.Allocator) []const u8 {
        return std.fmt.allocPrint(allocator, "%s", .{if (self.value) "true" else "false"});
    }
};

pub const Null = struct {
    pub fn Inspect() []const u8 {
        return "null";
    }
};
