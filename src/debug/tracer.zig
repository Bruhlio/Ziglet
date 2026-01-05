// src/debug/tracer.zig
const std = @import("std");
const VM = @import("../core/vm.zig").VM;
const Instruction = @import("../instruction/types.zig").Instruction;

pub const TraceLevel = enum {
    none, // No tracing
    minimal, // Just instruction execution
    standard, // Instructions + register changes
    verbose, // Full state changes after each instruction
    profile, // Include timing information
};

pub const TraceEntry = struct {
    pc: usize,
    instruction: Instruction,
    registers_before: ?[16]u32 = null,
    registers_after: ?[16]u32 = null,
    stack_depth: ?usize = null,
    cmp_flag: ?i8 = null,
    execution_time_ns: ?u64 = null,
    memory_accesses: ?[]MemoryAccess = null,

    pub const MemoryAccess = struct {
        address: usize,
        is_write: bool,
        size: u8,
        value: u32,
    };
};

pub const ExecutionTracer = struct {
    allocator: std.mem.Allocator,
    level: TraceLevel,
    trace_buffer: std.ArrayList(TraceEntry),
    current_entry: ?TraceEntry = null,
    timer: std.time.Timer,
    enabled: bool,
    memory_access_buffer: std.ArrayList(TraceEntry.MemoryAccess),

    pub fn init(allocator: std.mem.Allocator, level: TraceLevel) !ExecutionTracer {
        const timer = try std.time.Timer.start();
        return ExecutionTracer{
            .allocator = allocator,
            .level = level,
            .trace_buffer = try std.ArrayList(TraceEntry).initCapacity(allocator, 0),
            .timer = timer,
            .enabled = level != .none,
            .memory_access_buffer = try std.ArrayList(TraceEntry.MemoryAccess).initCapacity(allocator, 0),
        };
    }

    pub fn deinit(self: *ExecutionTracer) void {
        self.trace_buffer.deinit(self.allocator);
        self.memory_access_buffer.deinit(self.allocator);
    }

    pub fn beginInstruction(self: *ExecutionTracer, vm: *const VM) void {
        if (!self.enabled) return;

        self.timer.reset();

        var entry = TraceEntry{
            .pc = vm.pc,
            .instruction = vm.program[vm.pc],
        };

        if (self.level == .standard or self.level == .verbose or self.level == .profile) {
            entry.registers_before = vm.registers;
            entry.stack_depth = vm.stack.items.len;
            entry.cmp_flag = vm.cmp_flag;
        }

        self.current_entry = entry;
        self.memory_access_buffer.clearRetainingCapacity();
    }

    pub fn endInstruction(self: *ExecutionTracer, vm: *const VM) !void {
        if (!self.enabled or self.current_entry == null) return;

        var entry = self.current_entry.?;

        if (self.level == .standard or self.level == .verbose or self.level == .profile) {
            entry.registers_after = vm.registers;
        }

        if (self.level == .profile) {
            entry.execution_time_ns = self.timer.read();
        }

        if (self.level == .verbose) {
            if (self.memory_access_buffer.items.len > 0) {
                const accesses = try self.allocator.alloc(TraceEntry.MemoryAccess, self.memory_access_buffer.items.len);
                @memcpy(accesses, self.memory_access_buffer.items);
                entry.memory_accesses = accesses;
            }
        }

        try self.trace_buffer.append(self.allocator, entry);
    }

    pub fn recordMemoryAccess(self: *ExecutionTracer, address: usize, is_write: bool, size: u8, value: u32) !void {
        if (!self.enabled or self.level != .verbose) return;

        try self.memory_access_buffer.append(self.allocator,
        .{
            .address = address,
            .is_write = is_write,
            .size = size,
            .value = value,
        });
    }

    pub fn generateReport(self: *const ExecutionTracer) ![]u8 {
    if (self.trace_buffer.items.len == 0) return &[_]u8{};

    var buffer = try std.ArrayList(u8).initCapacity(self.allocator, 0);
    defer buffer.deinit(self.allocator);

    var temp_buf: [512]u8 = undefined;

    const line1 = try std.fmt.bufPrint(&temp_buf, "Execution Trace ({d} instructions)\n", .{self.trace_buffer.items.len});
    try buffer.appendSlice(self.allocator,line1);
    try buffer.appendSlice(self.allocator,"----------------------------------------\n");

    for (self.trace_buffer.items, 0..) |entry, i| {
        const line = try std.fmt.bufPrint(&temp_buf, "{d}: [PC={d}] {any}", .{ i, entry.pc, entry.instruction });
        try buffer.appendSlice(self.allocator, line);

        if (entry.registers_before) |regs_before| {
            try buffer.appendSlice(self.allocator, "\n  Regs before: ");
            for (regs_before, 0..) |reg, j| {
                if (reg != 0) {
                    const reg_line = try std.fmt.bufPrint(&temp_buf, "R{d}={d} ", .{ j, reg });
                    try buffer.appendSlice(self.allocator, reg_line);
                }
            }
        }

        if (entry.registers_after) |regs_after| {
            try buffer.appendSlice(self.allocator, "\n  Regs after:  ");
            for (regs_after, 0..) |reg, j| {
                if (reg != 0) {
                    const reg_line = try std.fmt.bufPrint(&temp_buf, "R{d}={d} ", .{ j, reg });
                    try buffer.appendSlice(self.allocator, reg_line);
                }
            }
        }

        if (entry.stack_depth) |depth| {
            const depth_line = try std.fmt.bufPrint(&temp_buf, "\n  Stack depth: {d}", .{depth});
            try buffer.appendSlice(self.allocator, depth_line);
        }

        if (entry.execution_time_ns) |exec_time| {
            const time_line = try std.fmt.bufPrint(&temp_buf, "\n  Exec time: {d}ns", .{exec_time});
            try buffer.appendSlice(self.allocator, time_line);
        }

        if (entry.memory_accesses) |accesses| {
            try buffer.appendSlice(self.allocator, "\n  Memory accesses:");
            for (accesses) |access| {
                const access_line = try std.fmt.bufPrint(&temp_buf, "\n    {s} addr={d} size={d} value={d}", .{
                    if (access.is_write) "WRITE" else "READ",
                    access.address,
                    access.size,
                    access.value,
                });
                try buffer.appendSlice(self.allocator, access_line);
            }
        }

        try buffer.appendSlice(self.allocator, "\n");
    }

    return try buffer.toOwnedSlice(self.allocator);
}

};
