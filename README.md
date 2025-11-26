# Memory Library

Essa biblioteca aqui é pra mexer na memória dos processos do Windows. Basicamente você consegue ler, escrever e fazer scan de memória de qualquer processo que tiver rodando. Bem útil pra quem mexe com reverse, cheats ou só quer fuçar mesmo. Se você é daqueles que usa Cheat Engine e não sabe programar, essa bostinha  aqui não vai te ajudar não, vai ter que aprender C++ primeiro gordinho.

## O que tem aqui

- Ler e escrever memória (int, float, long, bytes, o que quiser)
- AoB Scan pra achar padrões de bytes (com suporte a wildcards)
- Abrir processo por nome ou ID
- Validação automática das regiões de memória (pra não dar merda)
- Aceita endereço em hex string também
- Templates pra você usar qualquer tipo
- Limpa tudo sozinho quando fecha

## O que precisa

- Windows (7 pra cima)
- Compilador C++ que suporte C++11
- Visual Studio ou qualquer IDE que compile C++

## Arquivos

```
Memory/
├── Memory.hpp              # O gordinho principal (esse aqui faz tudo)
├── Memory.cpp               # Implementação (onde a mágica acontece)
├── Proc.hpp                # Info do processo (só estrutura, nada demais)
├── Imps.hpp                # Constantes (negrin de enum)
└── MemoryRegionResult.hpp  # Resultado das regiões (outro gordinho)
```

## Como usar

### Abrir processo

```cpp
#include "Memory.hpp"

using namespace MemoryLib;

Mem mem;

// Por nome (mais fácil)
if (mem.OpenProcess("notepad.exe")) {
    // Abriu, pode usar
}

// Ou pega o ID primeiro e abre depois
DWORD pid = mem.GetProcIdFromName("notepad.exe");
if (mem.OpenProcess(pid)) {
    // Pronto pra usar
}
```

### Ler memória

```cpp
// Lê int, float, long...
int value = mem.ReadInt(0x12345678);
float fValue = mem.ReadFloat(0x12345678);
long lValue = mem.ReadLong(0x12345678);

// Ou usa template (mais flexível)
auto value = mem.ReadMemory<int>(0x12345678);

// Aceita string hex também (bem mais fácil)
int value = mem.ReadInt("12345678");

// Ler vários bytes de uma vez
std::vector<BYTE> bytes = mem.ReadBytes(0x12345678, 16);
```

### Escrever memória

```cpp
// Escreve direto
mem.WriteMemory(0x12345678, 100);           // int
mem.WriteMemory(0x12345678, 3.14f);         // float
mem.WriteMemory(0x12345678, 1000L);         // long

// Com string hex
mem.WriteMemory("12345678", 100);

// Escreve bytes direto
std::vector<BYTE> data = {0x90, 0x90, 0xC3};
mem.WriteMemory(0x12345678, data);

// Ou passa tipo como string (útil quando não sabe o tipo em compile time)
mem.WriteMemory(0x12345678, "int", "100");
mem.WriteMemory(0x12345678, "float", "3.14");
mem.WriteMemory(0x12345678, "bytes", "90 90 C3");
```

### AoB Scan (Array of Bytes)

Essa é a parte mais útil. Você passa um padrão de bytes e ele acha todos os lugares onde esse padrão aparece na memória. Se você não sabe o que é AoB Scan, provavelmente é daqueles que só copia código do GitHub sem entender nada, negrin. Mas tudo bem, todo mundo começa de algum lugar.

```cpp
// Scan em toda a memória do processo
std::vector<DWORD_PTR> results = mem.AoBScan("48 89 5C 24 ?? 48 89 74 24");

// Scan em região específica (mais rápido)
DWORD_PTR start = 0x400000;
DWORD_PTR end = 0x500000;
std::vector<DWORD_PTR> results = mem.AoBScan(start, end, "48 89 5C 24 ?? 48");

// Só em regiões que dá pra escrever
results = mem.AoBScan("48 89 5C 24", true, false);

// Só em regiões executáveis
results = mem.AoBScan("48 89 5C 24", false, true);
```

**Formato do padrão:**
- Bytes exatos: `48 89 5C 24`
- Byte desconhecido: `??` ou `?` (qualquer valor)
- Nibble desconhecido: `?4` ou `4?` (só metade do byte)

### Coisas úteis

```cpp
// Ver se o processo tá aberto
if (mem.IsProcessOpen()) {
    // Tá aberto, pode usar
}

// Pega info do processo
Proc& proc = mem.GetProc();
HANDLE handle = proc.Handle;
bool is64bit = proc.Is64Bit;
MODULEINFO module = proc.MainModule;

// Converte hex string pra endereço
DWORD_PTR addr = Mem::HexStringToAddress("12345678");

// Fecha o processo (limpa tudo)
mem.CloseProcess();
```

## Exemplo completo

Aqui um exemplo básico de como usar tudo junto:

```cpp
#include "Memory.hpp"
#include <iostream>

using namespace MemoryLib;

int main() {
    Mem mem;
    
    // Abre o processo
    if (!mem.OpenProcess("notepad.exe")) {
        std::cout << "Não conseguiu abrir o processo" << std::endl;
        return 1;
    }
    
    // Faz scan procurando um padrão
    std::vector<DWORD_PTR> addresses = mem.AoBScan("48 89 5C 24 ??");
    
    if (!addresses.empty()) {
        DWORD_PTR foundAddr = addresses[0];
        std::cout << "Achei em: 0x" << std::hex << foundAddr << std::endl;
        
        // Lê o valor que tá lá
        int value = mem.ReadInt(foundAddr);
        std::cout << "Valor: " << std::dec << value << std::endl;
        
        // Escreve um valor novo
        mem.WriteMemory(foundAddr, 100);
        std::cout << "Escreveu!" << std::endl;
    }
    
    mem.CloseProcess();
    return 0;
}
```

## Como compilar

Se você não sabe compilar código C++, provavelmente não deveria estar mexendo com memória de processos não gordinho. Mas vou explicar mesmo assim pra essa negrin aqui.

### Visual Studio

Só adiciona os arquivos no projeto e compila. Não esquece de linkar:

```
psapi.lib
```

### CMake

```cmake
add_library(Memory STATIC
    Memory.cpp
    Memory.hpp
    Proc.hpp
    Imps.hpp
    MemoryRegionResult.hpp
)

target_link_libraries(Memory psapi)
```

### MinGW/GCC

```bash
g++ -std=c++11 -c Memory.cpp -o Memory.o
g++ -std=c++11 seu_programa.cpp Memory.o -lpsapi -o programa.exe
```

## Avisos importantes

- ⚠️ Alguns processos precisam de admin pra acessar (se não tiver admin, essa negrin não funciona)
- ⚠️ O processo tem que estar rodando (óbvio né gordinho)
- ⚠️ Endereços mudam entre execuções (ASLR existe por um motivo, não é bug)
- ⚠️ Use com responsabilidade, não vai fazer merda em processo dos outros
- ⚠️ Se der crash no processo alvo, provavelmente você escreveu merda na memória errada

## Resenha

Essa biblioteca foi feita pra ser simples de usar. Não tem muita frescura, só funciona. Se você precisa de algo mais complexo, provavelmente vai ter que fazer na mão mesmo gordinho. Mas pra maioria dos casos, isso aqui resolve.

O AoB Scan pode ser meio lento dependendo do tamanho do processo, mas é o preço que se paga por fazer scan completo. Se souber a região exata, sempre passa start/end que fica bem mais rápido. Se você tá reclamando que tá lento, provavelmente tá fazendo scan em processo gigante sem filtrar região, negrin.

A parte de templates é bem útil quando você não sabe o tipo em compile time, mas na maioria das vezes os métodos específicos (ReadInt, ReadFloat, etc) são mais fáceis de usar. Se você não sabe o que é template, vai estudar C++ antes de vir aqui fazer pergunta besta.

Se você é daqueles que copia código e não entende nada, pelo menos tenta ler os comentários. Não vem no GitHub Issues perguntando coisa que tá escrito aqui, gordinho.

Enfim, é isso. Se tiver dúvida, olha o código que é bem direto ao ponto. Se ainda não entender, o problema é você, não a biblioteca.
