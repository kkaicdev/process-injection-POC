# 💉 Remote Process Injector - Proof of Concept

Esta projeto é uma **PoC (Proof of Concept)** de uma técnica clássica de injeção de código em processos remotos no Windows. Através do uso de chamadas diretas à API nativa do sistema, ele injeta um shellcode diretamente na memória de um processo alvo, utilizando as seguintes funções:

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

- Desenvolvido em C# com .NET 8.0
- Compilado usando o compilador de linha de comando csc (C# Compiler)
- Utiliza P/Invoke para chamadas às funções da API Win32.
- O shellcode binário foi gerado com msfvenom (arquitetura x64).
- Testado e executado em ambiente Windows.
