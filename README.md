# Projekt: Substituční šifra – šifrování, dešifrování a kryptoanalýza

Tento projekt slouží k šifrování a dešifrování textu pomocí **substituční šifry** a k **automatickému prolomení šifry** pomocí statistické metody (kombinace bigramové a trigramové analýzy).

## Složky a soubory

- `main.py` – hlavní rozhraní v terminálu (šifrování, dešifrování, prolomení)
- `kryptolib.py` – vlastní knihovna se všemi potřebnými funkcemi
- `notebook.ipynb` – demonstrační Jupyter sešit (pro šifrování a analýzu krok po kroku)
- `krakatit.txt` – referenční text pro bigramy a trigramy
- `wordlist.txt` – slovník českých slov pro hodnocení dešifrovaných vět
- `ToCipher/` – vstupní soubory k zašifrování
- `Cipher/` – šifrované soubory k ručnímu dešifrování
- `Encrypted/` – výstupy šifrování (text + klíč)
- `Decrypted/` – výsledky dešifrování a kryptoanalýzy

## Funkce

- Generování náhodného klíče pro substituci
- Možnost zadat vlastní klíč
- Šifrování a dešifrování souborů
- Automatické prolomení šifry pomocí:
  - Metropolis-Hastings algoritmu
  - Bigramové + trigramové analýzy
  - Skóre podle výskytu slov ze slovníku

## Spuštění

Spusť příkaz:

```bash
python main.py
