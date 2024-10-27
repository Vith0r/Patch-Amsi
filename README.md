# PATCH AMSI 🐱‍💻
<img src="https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=appveyor" alt="Windows">

⚠️ **Aviso**  
> **Este código foi desenvolvido para fins educativos e de pesquisa em segurança. Não o utilize para propósitos maliciosos.**

## Visão Geral do Projeto

Este é um projeto básico escrito em C++, que tem a capacidade de realizar um patch na DLL do `amsi.dll` em um processo do `powershell.exe` que esteja em execução.

### Como funciona:

1. Localiza o processo `powershell.exe` e obtém seu ID.
2. Carrega a biblioteca `amsi.dll` e encontra a função `AmsiScanBuffer`.
3. Calcula o endereço do `AmsiScanBuffer` + `0x95` para chegar no endereço necessário da função para aplicar o patch.
4. Modifica as permissões de memória para permitir a escrita e altera um byte (de `0x74` para `0x75`), conseguindo assim "desativar" a verificação de segurança do AMSI.
5. Restaura as permissões de memória e finaliza.

## Demonstração

![1](https://i.imgur.com/BJIKHhA.png)
![2](https://i.imgur.com/ouoMuKj.png)

## Vídeo de Demonstração

<a href="https://www.youtube.com/watch?v=vuxUc-rutq4" target="_blank">
    <img src="https://img.youtube.com/vi/vuxUc-rutq4/0.jpg" alt="Assistir vídeo" width="800" />
</a>
