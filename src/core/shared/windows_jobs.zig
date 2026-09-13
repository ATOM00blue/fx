//! Windows Job Object wrappers giving a parent process control over a child
//! process's entire descendant tree, mirroring the process-group semantics the
//! command runner uses on POSIX.
//!
//! Every entry point here is only referenced from `comptime` Windows branches
//! in the command runner, so on other targets none of the declarations below
//! are analyzed and nothing links against kernel32.

const std = @import("std");
const builtin = @import("builtin");

const windows = std.os.windows;

/// Exit code reported for processes terminated through a job.
const terminate_exit_code: windows.UINT = 1;

/// Access rights required to add a process to a job object.
const process_assignment_access: windows.DWORD =
    PROCESS_SET_QUOTA | PROCESS_TERMINATE;

const JOBOBJECTINFOCLASS = c_int;
const JobObjectBasicAccountingInformation: JOBOBJECTINFOCLASS = 1;
const JobObjectExtendedLimitInformation: JOBOBJECTINFOCLASS = 9;

const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: windows.DWORD = 0x2000;

const PROCESS_SET_QUOTA: windows.DWORD = 0x0100;
const PROCESS_TERMINATE: windows.DWORD = 0x0001;

extern "kernel32" fn CreateJobObjectW(
    lpJobAttributes: ?*const windows.SECURITY_ATTRIBUTES,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn SetInformationJobObject(
    hJob: windows.HANDLE,
    JobObjectInformationClass: JOBOBJECTINFOCLASS,
    lpJobObjectInformation: *anyopaque,
    cbJobObjectInformationLength: windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn AssignProcessToJobObject(
    hJob: windows.HANDLE,
    hProcess: windows.HANDLE,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn TerminateJobObject(
    hJob: windows.HANDLE,
    uExitCode: windows.UINT,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn QueryInformationJobObject(
    hJob: windows.HANDLE,
    JobObjectInformationClass: JOBOBJECTINFOCLASS,
    lpJobObjectInformation: *anyopaque,
    cbJobObjectInformationLength: windows.DWORD,
    lpReturnLength: ?*windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: windows.DWORD,
    bInheritHandle: windows.BOOL,
    dwProcessId: windows.DWORD,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn ResumeThread(hThread: windows.HANDLE) callconv(.winapi) windows.DWORD;

const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: windows.LARGE_INTEGER,
    PerJobUserTimeLimit: windows.LARGE_INTEGER,
    LimitFlags: windows.DWORD,
    MinimumWorkingSetSize: windows.SIZE_T,
    MaximumWorkingSetSize: windows.SIZE_T,
    ActiveProcessLimit: windows.DWORD,
    Affinity: windows.ULONG_PTR,
    PriorityClass: windows.DWORD,
    SchedulingClass: windows.DWORD,
};

const IO_COUNTERS = extern struct {
    ReadOperationCount: windows.ULONG64,
    WriteOperationCount: windows.ULONG64,
    OtherOperationCount: windows.ULONG64,
    ReadTransferCount: windows.ULONG64,
    WriteTransferCount: windows.ULONG64,
    OtherTransferCount: windows.ULONG64,
};

const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: windows.SIZE_T,
    JobMemoryLimit: windows.SIZE_T,
    PeakProcessMemoryUsed: windows.SIZE_T,
    PeakJobMemoryUsed: windows.SIZE_T,
};

const JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = extern struct {
    TotalUserTime: windows.LARGE_INTEGER,
    TotalKernelTime: windows.LARGE_INTEGER,
    ThisPeriodTotalUserTime: windows.LARGE_INTEGER,
    ThisPeriodTotalKernelTime: windows.LARGE_INTEGER,
    TotalPageFaultCount: windows.LONG,
    TotalProcesses: windows.LONG,
    ActiveProcesses: windows.LONG,
    TotalTerminatedProcesses: windows.LONG,
};

/// A Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: every
/// process assigned to the job, including all descendants, is terminated when
/// the last handle to the job closes.
pub const Job = struct {
    handle: ?windows.HANDLE = null,

    pub const Error = error{
        JobCreationFailed,
        JobConfigurationFailed,
        ProcessOpenFailed,
        ProcessAssignmentFailed,
    };

    /// Creates a kill-on-close job object and assigns an already-open process
    /// handle to it. This is the shape `std.process.Child` exposes on Windows,
    /// where `child.id` is the process handle from CreateProcessW. Ownership
    /// of `process` stays with the caller; job membership outlives the handle.
    pub fn forProcess(process: windows.HANDLE) Error!Job {
        const job = CreateJobObjectW(null, null) orelse
            return error.JobCreationFailed;
        var configured = false;
        defer if (!configured) windows.CloseHandle(job);
        var info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            std.mem.zeroes(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info,
            @sizeOf(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
        ) == .FALSE) return error.JobConfigurationFailed;
        if (AssignProcessToJobObject(job, process) == .FALSE)
            return error.ProcessAssignmentFailed;
        configured = true;
        return .{ .handle = job };
    }

    /// Creates a kill-on-close job object for the process with id `pid`,
    /// opening the process with `PROCESS_SET_QUOTA | PROCESS_TERMINATE` for
    /// the assignment and closing that temporary handle afterwards.
    pub fn forProcessId(pid: windows.DWORD) Error!Job {
        const process = OpenProcess(process_assignment_access, .FALSE, pid) orelse
            return error.ProcessOpenFailed;
        defer windows.CloseHandle(process);
        return forProcess(process);
    }

    /// Requests termination of every process in the job (the whole tree).
    /// Asynchronous and idempotent: safe to call repeatedly and on jobs whose
    /// processes have already exited.
    pub fn terminate(self: *Job) void {
        const job = self.handle orelse return;
        _ = TerminateJobObject(job, terminate_exit_code);
    }

    /// Closes the job handle. With `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` the
    /// kernel terminates any processes still assigned to the job, so closing
    /// doubles as the last-resort cleanup for stragglers. Idempotent.
    pub fn close(self: *Job) void {
        const job = self.handle orelse return;
        self.handle = null;
        windows.CloseHandle(job);
    }

    /// Reports whether the job still contains live processes. Used to decide
    /// whether to keep waiting after the captured streams have closed, the
    /// same role `kill(-pgid, 0)` plays on POSIX.
    pub fn hasActiveProcesses(self: *const Job) bool {
        const job = self.handle orelse return false;
        var info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = undefined;
        if (QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &info,
            @sizeOf(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION),
            null,
        ) == .FALSE) {
            // If the query fails, assume processes remain so callers keep
            // waiting rather than abandoning a live tree.
            return true;
        }
        return info.ActiveProcesses > 0;
    }
};

/// Releases a child process created with a suspended primary thread after its
/// job assignment has been settled. Windows-only; a no-op failure is ignored
/// because the thread handle is owned by the caller and freshly created.
pub fn resumeProcessThread(thread: windows.HANDLE) void {
    _ = ResumeThread(thread);
}

comptime {
    if (builtin.os.tag == .windows) {
        // Force analysis of the public surface under the Windows target so
        // signature drift against kernel32 is caught even in builds that do
        // not spawn children.
        _ = &Job.forProcess;
        _ = &Job.forProcessId;
        _ = &Job.terminate;
        _ = &Job.close;
        _ = &Job.hasActiveProcesses;
    }
}
