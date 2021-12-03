// **** **** **** **** **** **** **** **** **** **** **** **** **** **** **** ****

// first: identify upx packed code
// UPX packed
// approach reusing rules for score based hunting/investigations

private rule magicbytes_pe : MagicBytes 
{
    meta:
        description = "Find the PE magic bytes and IMAGE_NT_HEADERS Signature"

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x4550
}


//rule arch_pe_64bit : Arch PE
//{
//    meta:
//        description = "clean up in arch_pe_64bit_importedPEModule"
//    condition:
//        magicbytes_pe and
//        uint16(uint32(0x3C)+0x4) == 0x8664 and
//        uint16(uint32(0x3C)+0x04 + 0x10) != 0x00 and
//        uint16(uint32(0x3C)+0x04 + 0x14) == 0x020B
//}

private rule filesize_gt_1dot5MB
{
    condition:
        filesize > 1500KB
}

private rule filesize_lt_5MB
{
    condition:
        filesize < 5MB
}

//rule packer_upx_win : Packers
//{
//    meta:
//        description = "Find characteristics of upx packer usage"
//        description = "clean up in packer_upx_win_importedPEModule"
//    strings:
//        $s_01 = "UPX!"
//        $import_01 = "VirtualProtect"
//        $import_02 = "LoadLibraryA"
//        $import_03 = "GetProcAddress"
//        $import_04 = "VirtualAlloc"
//    condition:
//        arch_pe_64bit and
//        uint32(uint32(0x3C)+ 0x04 + 0x14 + uint16(uint32(0x3C) + 0x04 + 0x10)) == 0x30585055 and
//        uint32(uint32(0x3C)+ 0x04 + 0x14 + uint16(uint32(0x3C) + 0x04 + 0x10) + 0x10) == 0x0 and
//        uint32(uint32(0x3C)+ 0x04 + 0x14 + uint16(uint32(0x3C) + 0x04 + 0x10) + 0x28 + 0x0C) - uint32(uint32(0x3C)+ 0x04 + 0x14 + uint16(uint32(0x3C) + 0x04 + 0x10) + 0x0C) > 0 and
//        uint32(uint32(0x3C)+ 0x04 + 0x14 + uint16(uint32(0x3C) + 0x04 + 0x10) + 0x28) == 0x31585055 and        
//        math.entropy((uint32(uint32(0x3C)+ 0x04 + 0x14 + uint16(uint32(0x3C) + 0x04 + 0x10) + 0x28 + 0x14)),(uint32(uint32(0x3C)+ 0x04 + 0x14 + uint16(uint32(0x3C) + 0x04 + 0x10) + 0x28 + 0x10))) > 8 * 0.965 and
//        all of ($import_*) and
//        all of ($s_*)
// }

import "pe"
import "math"

rule arch_pe_64bit_importedPEModule : Arch PE
{
    condition:
        magicbytes_pe and
        pe.machine == pe.MACHINE_AMD64 and
        pe.size_of_optional_header != 0 and // no coff
        pe.opthdr_magic == 0x20B
        
}

// what is already known on UPX: UPX0 has a raw size of 0 and virtual_size > 0, second section is UPX1 and has an entropy > 96.5 %, the default imports are known
rule packer_upx_win_importedPEModule : Packers
{
    meta:
        author = "rchrdwss, 0x7373776472686372@protonmail.com"
        description = "Find characteristics of upx packed"
    strings:
        $s_01 = "UPX!"
        $import_01 = "VirtualProtect"
        $import_02 = "LoadLibraryA"
        $import_03 = "GetProcAddress"
        $import_04 = "VirtualAlloc"
    condition:
        magicbytes_pe and
        pe.sections[0].name == "UPX0" and
        pe.sections[0].raw_data_size == 0 and
        pe.sections[0].virtual_size > 0 and
        pe.sections[1].name == "UPX1" and
        math.entropy(pe.sections[1].raw_data_offset, pe.sections[1].raw_data_size) > 8 * 0.965 and
        all of ($import_*) and
        all of ($s_*)
}

private rule compiled_with_go {
    meta:
        description = "thanks to michael hunhoff and his provided capa rule"
        description = "don't use without file format information"
    strings:
        $s_1 = "Go build ID:" fullword
        $s_2 = "go.buildid"
        $s_3 = "Go buildinf:" fullword
    condition:
        any of them
}

// least file size because of GO compiling behavior of imports
// this is only a demonstrator for usage of scoring
rule upx_packed_limits_scorebasedhunting
{
    meta:
        author = "rchrdwss, 0x7373776472686372@protonmail.com"
        date = "20211123"
        version = "0.1"
        status = "tetsing only"
        description = "testing a score based hunting for files: strong indicators + 10 pts, medium + 5 pts, weak + 1 pts, also good for reduction, would be pleased to discuss your ideas"
        tlp = "TLP:white"
        yara_versions = "> 3.3, 4.x"
        hash = "b9a2c986b6ad1eb4cfb0303baede906936fe96396f3cf490b0984a4798d741d8"
    condition:
        math.to_number(packer_upx_win_importedPEModule) * 10 
            + math.to_number(arch_pe_64bit_importedPEModule) * 5 // + 32bit version * 1
            + math.to_number(filesize_gt_1dot5MB) * 5 + math.to_number(filesize_lt_5MB) * 5 // other file sizes only * 1 multiplier
            + math.to_number(compiled_with_go) * 5
            >= 25
            // adding versions of UPX with different multipliers
}
