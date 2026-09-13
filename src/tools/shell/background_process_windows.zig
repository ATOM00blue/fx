//! Windows process-identity and tree-control helpers for the background
//! process provider. POSIX uses PID + boot-id + start-time tokens and signal
//! process groups; the Windows equivalents are PID + process creation time
//! (stable across PID reuse) and a Toolhelp32 snapshot walk terminated with
//! TerminateProcess.
const std = @import("std");
const builtin = @import("builtin");
const io_mod = @import("../../core/shared/io.zig");
const process_supervisor = @import(
    "../../core/background/process_supervisor.zig",
);
const background_process_provider = @import(
    "../../core/execution/background_process_provider.zig",
);
const debug_trace = @import("../../core/shared/debug_trace.zig");

const windows = std.os.windows;
const Allocator = std.mem.Allocator;

comptime {
    if (builtin.os.tag == .windows) {
        // Force analysis of this module's public surface for the Windows
        // target; on other targets nothing here is imported.
        _ = captureToken;
        _ = processAlive;
        _ = terminatePidTree;
        _ = processIdFromHandle;
    }
}

const STILL_ACTIVE: u32 = 259;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_TERMINATE: u32 = 0x0001;
const TH32CS_SNAPPROCESS: u32 = 0x00000002;

const FILETIME = extern struct {
    low: u32,
    high: u32,
};

const ProcessEntry32W = extern struct {
    size: u32,
    cnt_usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    pri_class_base: i32,
    flags: u32,
    exe_file: [260]u16,
};

extern "kernel32" fn OpenProcess(
    desired_access: u32,
    inherit_handle: windows.BOOL,
    process_id: u32,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn GetProcessTimes(
    process: windows.HANDLE,
    creation_time: *FILETIME,
    exit_time: *FILETIME,
    kernel_time: *FILETIME,
    user_time: *FILETIME,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn GetExitCodeProcess(
    process: windows.HANDLE,
    exit_code: *u32,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn GetProcessId(
    process: windows.HANDLE,
) callconv(.winapi) u32;

extern "kernel32" fn TerminateProcess(
    process: windows.HANDLE,
    exit_code: u32,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn CloseHandle(
    handle: windows.HANDLE,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn CreateToolhelp32Snapshot(
    flags: u32,
    process_id: u32,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn Process32FirstW(
    snapshot: windows.HANDLE,
    entry: *ProcessEntry32W,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn Process32NextW(
    snapshot: windows.HANDLE,
    entry: *ProcessEntry32W,
) callconv(.winapi) windows.BOOL;

/// `std.process.Child.id` is the hProcess handle on Windows, not the pid.
pub fn processIdFromHandle(handle: windows.HANDLE) u32 {
    return GetProcessId(handle);
}

/// Identity of the running process `pid_text`: creation time in Windows
/// FILETIME units, unique per process instance (and across boots, being
/// absolute time since 1601). Exited processes report `ProcessNotFound` even
/// while a retained handle keeps the kernel object alive.
pub fn captureToken(
    alloc: Allocator,
    pid_text: []const u8,
) background_process_provider.ProviderError!process_supervisor.ProcessInstanceToken {
    _ = alloc;
    const pid = std.fmt.parseInt(u32, pid_text, 10) catch
        return error.InvalidPid;
    const process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        .FALSE,
        pid,
    ) orelse return error.ProcessNotFound;
    defer _ = CloseHandle(process);

    var exit_code: u32 = 0;
    if (!GetExitCodeProcess(process, &exit_code).toBool()) {
        return error.ProcessIdentityUnavailable;
    }
    if (exit_code != STILL_ACTIVE) return error.ProcessNotFound;

    var creation: FILETIME = .{ .low = 0, .high = 0 };
    var exit_ft: FILETIME = undefined;
    var kernel_ft: FILETIME = undefined;
    var user_ft: FILETIME = undefined;
    if (!GetProcessTimes(process, &creation, &exit_ft, &kernel_ft, &user_ft).toBool()) {
        return error.ProcessIdentityUnavailable;
    }
    const creation_value = (@as(u64, creation.high) << 32) | creation.low;
    if (creation_value == 0) return error.ProcessIdentityUnavailable;

    var token_buf: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&token_buf, "windows:{d}", .{creation_value}) catch
        return error.ProcessIdentityUnavailable;
    return process_supervisor.ProcessInstanceToken.parse(text) catch
        error.ProcessIdentityUnavailable;
}

pub fn processAlive(pid_text: []const u8) bool {
    const pid = std.fmt.parseInt(u32, pid_text, 10) catch return false;
    const process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        .FALSE,
        pid,
    ) orelse return false;
    defer _ = CloseHandle(process);
    var exit_code: u32 = 0;
    if (!GetExitCodeProcess(process, &exit_code).toBool()) return true;
    return exit_code == STILL_ACTIVE;
}

/// Hard-terminates `pid_text` and every descendant, deepest first. Windows has
/// no deliverable SIGTERM for detached console processes, so this mirrors the
/// POSIX force-kill stage directly.
pub fn terminatePidTree(pid_text: []const u8) bool {
    const root_pid = std.fmt.parseInt(u32, pid_text, 10) catch return false;

    var descendants: [512]u32 = undefined;
    const count = collectDescendants(root_pid, &descendants);

    var terminated = false;
    var index: usize = count;
    while (index > 0) {
        index -= 1;
        if (terminateProcessById(descendants[index])) terminated = true;
    }
    if (terminateProcessById(root_pid)) terminated = true;
    if (terminated) {
        debug_trace.logf(
            "background",
            "terminated background process tree pid={d} descendants={d}",
            .{ root_pid, count },
        );
    }
    return terminated;
}

fn terminateProcessById(pid: u32) bool {
    const process = OpenProcess(
        PROCESS_TERMINATE,
        .FALSE,
        pid,
    ) orelse return false;
    defer _ = CloseHandle(process);
    return TerminateProcess(process, 1).toBool();
}

fn collectDescendants(root_pid: u32, out: []u32) usize {
    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) orelse return 0;
    defer _ = CloseHandle(snapshot);

    var entries: [1024]PidPair = undefined;
    var count: usize = 0;
    var entry: ProcessEntry32W = undefined;
    entry.size = @sizeOf(ProcessEntry32W);
    var has_first = Process32FirstW(snapshot, &entry).toBool();
    while (has_first and count < entries.len) {
        entries[count] = .{
            .pid = entry.process_id,
            .ppid = entry.parent_process_id,
        };
        count += 1;
        has_first = Process32NextW(snapshot, &entry).toBool();
    }

    var descendants_len: usize = 0;
    appendDescendants(entries[0..count], root_pid, out, &descendants_len);
    return descendants_len;
}

const PidPair = struct {
    pid: u32,
    ppid: u32,
};

fn appendDescendants(
    pairs: []const PidPair,
    parent_pid: u32,
    out: []u32,
    out_len: *usize,
) void {
    for (pairs) |pair| {
        if (pair.ppid != parent_pid) continue;
        appendDescendants(pairs, pair.pid, out, out_len);
        if (out_len.* >= out.len) return;
        out[out_len.*] = pair.pid;
        out_len.* += 1;
    }
}

test "windows descendant walk orders deepest first" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    _ = alloc;

    const pairs = [_]PidPair{
        .{ .pid = 10, .ppid = 1 },
        .{ .pid = 11, .ppid = 10 },
        .{ .pid = 12, .ppid = 11 },
        .{ .pid = 13, .ppid = 10 },
        .{ .pid = 14, .ppid = 99 },
    };
    var out: [16]u32 = undefined;
    var out_len: usize = 0;
    appendDescendants(&pairs, 10, &out, &out_len);
    try std.testing.expectEqualSlices(u32, &.{ 12, 11, 13 }, out[0..out_len]);
}
