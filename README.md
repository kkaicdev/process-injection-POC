# 💉 Remote Process Injector - Proof of Concept

(EN-US) This project is a PoC (Proof of Concept) demonstrating a classic technique of code injection into remote processes on Windows. By using direct calls to the native Windows API, it injects shellcode directly into the memory of a target process, utilizing the following functions:

- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- CreateRemoteThread

⚠️ Warning: This project is intended for educational and research purposes only. Use responsibly.

---

## How it works:
The project injects shellcode into a remote process through the following steps:

1. Lists all running processes.
2. Prompts the user for the target process PID.
3. Loads shellcode from an external binary file.
4. Opens the process with sufficient permissions.
5. Allocates an executable memory region inside the remote process.
6. Writes the shellcode to the allocated memory.
7. Creates a remote thread that executes the injected shellcode.

This technique is known as Remote Thread Injection or Shellcode Injection via CreateRemoteThread and is commonly referenced in the MITRE ATT&CK framework as:

- **T1055 – Process Injection**
  - Sub-technique: T1055.002 – Portable Executable Injection

## Structure:

- Program: Main application logic.
- Injector: Implements injection logic using Win32 API calls.
- ShellcodeLoader: Loads shellcode from an external binary file.
- ProcessHelper: Lists running processes and verifies the provided PID.
- Logger: Formats output to the console.

## Environment:

- Tested and run on Windows environment.
- Developed in C# with .NET 8.0.
- Uses P/Invoke to call Win32 API functions.
- Shellcode binary was generated using msfvenom (x64 architecture).
- Compiled using the command-line compiler csc (C# Compiler).

---

(PT-BR) Esta projeto é uma **PoC (Proof of Concept)** de uma técnica clássica de injeção de código em processos remotos no Windows. Através do uso de chamadas diretas à API nativa do sistema, ele injeta um shellcode diretamente na memória de um processo alvo, utilizando as seguintes funções:

- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- CreateRemoteThread

⚠️ Atenção: Este projeto é apenas para fins educacionais e de pesquisa. Use com responsabilidade.

---

## Como funciona:

O projeto injeta um shellcode em um processo remoto através das seguintes etapas:

1. Lista todos os processos em execução.
2. Solicita ao usuário o PID do processo alvo.
3. Carrega o shellcode de um arquivo binário externo.
4. Abre o processo com permissões suficientes.
5. Aloca uma região de memória executável dentro do processo remoto.
6. Escreve o shellcode na memória alocada.
7. Cria uma thread remota que executa o shellcode injetado.

Essa técnica é conhecida como **Remote Thread Injection** ou **Shellcode Injection via CreateRemoteThread** e é comumente referenciada na MITRE ATT&CK como:

- **T1055 – Process Injection**
  - Subtécnica: **T1055.002 – Portable Executable Injection**

## Estrutura:

- Program: Lógica principal da aplicação.
- Injector: Implementa a lógica de injeção utilizando chamadas à API Win32.
- ShellcodeLoader: Responsável por carregar o shellcode a partir de arquivo binário externo.
- ProcessHelper: Lista processos e verifica o PID informado.
- Logger: Saída formatada para o console.

## Ambiente:

- Testado e executado em ambiente Windows.
- Desenvolvido em C# com .NET 8.0.
- Utiliza P/Invoke para chamadas às funções da API Win32.
- o arquivo binário externo foi gerado com msfvenom (arquitetura x64).
- Compilado usando o compilador de linha de comando **csc** (C# Compiler).

