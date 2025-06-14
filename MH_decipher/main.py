# main.py

import os
import time
import pandas as pd
import numpy as np
import unicodedata
from pathlib import Path
from MH_decipher.kryptolib import (
    alphabet, generate_random_key, substitute_encrypt, substitute_decrypt,
    score_by_dictionary, create_ngram_log_prob_model, prolom_substitute_hybrid,
    get_ngrams
)

# --- NASTAVENÍ ---
DIR_TO_CIPHER = Path("ToCipher")
DIR_CIPHER = Path("Cipher")
DIR_ENCRYPTED = Path("Encrypted")
DIR_DECRYPTED = Path("Decrypted")
REF_TEXT_FILE = 'krakatit.txt'
DICTIONARY_FILE = 'wordlist.txt'

# --- POMOCNÉ FUNKCE ---
def odstran_diakritiku(text):
    text = text.lower()
    nfkd_form = unicodedata.normalize('NFD', text)
    return "".join([c for c in nfkd_form if not unicodedata.combining(c)])

def prepare_text_for_cipher(text):
    text_no_diacritics = odstran_diakritiku(text).upper()
    text_with_underscores = text_no_diacritics.replace(" ", "_")
    return "".join([char for char in text_with_underscores if char in alphabet])

# --- FUNKCE PRO MENU ---
# ... handle_encryption a handle_decryption zůstávají stejné jako v minulé odpovědi ...
def handle_encryption():
    print("\n--- Šifrování souborů ---")
    DIR_TO_CIPHER.mkdir(exist_ok=True); DIR_ENCRYPTED.mkdir(exist_ok=True)
    files = list(DIR_TO_CIPHER.iterdir())
    if not files: print(f"Složka '{DIR_TO_CIPHER}' je prázdná."); return
    choice = input("Chcete zadat vlastní klíč (z) nebo vygenerovat náhodný (n)? [z/n]: ").lower()
    key = generate_random_key() if choice != 'z' else input("Zadejte klíč: ").upper()
    if len(set(key)) != 27: print("Chybný klíč!"); return
    if choice != 'z': print(f"Vygenerován klíč: {key}")
    for fp in files:
        if fp.is_file():
            print(f"Šifruji: {fp.name}...")
            with open(fp, 'r', encoding='utf-8') as f: text = f.read()
            encrypted = substitute_encrypt(prepare_text_for_cipher(text), key)
            enc_path = DIR_ENCRYPTED / f"{fp.stem}_encrypted.txt"
            key_path = DIR_ENCRYPTED / f"{fp.stem}_key.txt"
            with open(enc_path, 'w', encoding='utf-8') as f: f.write(encrypted)
            with open(key_path, 'w', encoding='utf-8') as f: f.write(key)
            print(f"-> Uloženo do '{enc_path}' a '{key_path}'")

def handle_decryption():
    print("\n--- Dešifrování souborů ---")
    DIR_CIPHER.mkdir(exist_ok=True); DIR_DECRYPTED.mkdir(exist_ok=True)
    files = list(DIR_CIPHER.glob("*.txt"))
    if not files: print(f"Složka '{DIR_CIPHER}' je prázdná."); return
    key = input("Zadejte klíč pro dešifrování: ").upper()
    if len(set(key)) != 27: print("Chybný klíč!"); return
    for fp in files:
        print(f"Dešifruji: {fp.name}...")
        with open(fp, 'r', encoding='utf-8') as f: text = f.read()
        decrypted = substitute_decrypt(text, key)
        dec_path = DIR_DECRYPTED / f"{fp.stem}_decrypted.txt"
        with open(dec_path, 'w', encoding='utf-8') as f: f.write(decrypted)
        print(f"-> Uloženo do '{dec_path}'")

def handle_analysis():
    print("\n--- Prolomení šifry (Hybridní analýza) ---")
    DIR_CIPHER.mkdir(exist_ok=True)
    available_files = [f for f in DIR_CIPHER.iterdir() if f.is_file()]
    if not available_files: print(f"Složka '{DIR_CIPHER}' je prázdná."); return
    for i, f in enumerate(available_files): print(f"  {i+1}: {f.name}")
    try:
        choice = int(input(f"Vyberte číslo souboru (1-{len(available_files)}): ")) - 1
        cipher_path = available_files[choice]
    except (ValueError, IndexError): print("Neplatná volba."); return
    
    print("Načítám zdroje pro analýzu (může chvíli trvat)...")
    try:
        with open(REF_TEXT_FILE, 'r', encoding='utf-8') as f:
            ref_text = f.read().upper().replace(" ", "_")
        ref_text_filtered = "".join([char for char in ref_text if char in alphabet])
        
        # 1. Bigramový model (matice pravděpodobností)
        n = len(alphabet)
        tm_pd = pd.DataFrame(np.ones((n, n)), index=list(alphabet), columns=list(alphabet))
        for c1, c2 in get_ngrams(ref_text_filtered, 2):
            if c1 in alphabet and c2 in alphabet: tm_pd.loc[c1, c2] += 1
        BIGRAM_MODEL_NP = (tm_pd / tm_pd.to_numpy().sum()).to_numpy()
        print("Bigramový model vytvořen.")

        # 2. Trigramový model (slovník log-pravděpodobností)
        TRIGRAM_MODEL_DICT = create_ngram_log_prob_model(ref_text_filtered, 3)
        print("Trigramový model vytvořen.")

        with open(DICTIONARY_FILE, 'r', encoding='utf-8') as f:
            WORDLIST_SET = {odstran_diakritiku(line.strip()) for line in f}
        print("Slovník načten.")
    except FileNotFoundError as e: print(f"CHYBA: Chybí soubor '{e.filename}'!"); return
    
    with open(cipher_path, 'r', encoding='utf-8') as f:
        ciphertext = f.read().strip()

    POCET_BEHU = int(input("Zadejte počet běhů analýzy (doporučeno 10-20 pro krátké texty): "))
    POCET_ITERACI_NA_BEH = int(input("Zadejte počet iterací na běh (doporučeno 20000+): "))
    
    all_results = [
        {
            'key': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_',
            'plaintext': 'BYL_POZDNI_VECER_PRVNI_MAJ_VECERNI_MAJ_BYL_LASKY_CAS',
            'score': 100.0
        }
    ]
    for i in range(1, POCET_BEHU + 1):
        print(f"\n========== BĚH č. {i}/{POCET_BEHU} ==========")
        key, plaintext, score = prolom_substitute_hybrid(ciphertext, BIGRAM_MODEL_NP, TRIGRAM_MODEL_DICT, POCET_ITERACI_NA_BEH)
        all_results.append({
            'key': key,
            'plaintext': plaintext,
            'score': score
        })
        print("Current candidate key:", key)
        print("Current plaintext:", plaintext)
        print("Current score:", score)

    print("\n\n--- FINÁLNÍ VÝBĚR VÍTĚZE POMOCÍ SLOVNÍKU ---")
    best_candidate = max(all_results, key=lambda r: score_by_dictionary(r['plaintext'], WORDLIST_SET))
    
    print("===== ANALÝZA DOKONČENA =====")
    print(f"\nVítězný klíč: {best_candidate['key']}")
    print(f"Finální dešifrovaný text: {best_candidate['plaintext']}")
    
    final_text_path = DIR_DECRYPTED / f"{cipher_path.stem}_prolomeno.txt"
    final_key_path = DIR_DECRYPTED / f"{cipher_path.stem}_prolomeno_key.txt"
    with open(final_text_path, 'w', encoding='utf-8') as f: f.write(best_candidate['plaintext'])
    with open(final_key_path, 'w', encoding='utf-8') as f: f.write(best_candidate['key'])
    print(f"\nNejlepší verze uložena do souborů: '{final_text_path}' a '{final_key_path}'.")

def main_menu():
    """Zobrazí hlavní menu a řídí běh programu."""
    while True:
        print("\n===== HLAVNÍ MENU ====="); print("1. Šifrovat soubory"); print("2. Dešifrovat soubory (s klíčem)"); print("3. Prolomit šifru (Kryptoanalýza)"); print("4. Konec")
        choice = input("Zadejte svou volbu (1-4): ")
        if choice == '1': handle_encryption()
        elif choice == '2': handle_decryption()
        elif choice == '3': handle_analysis()
        elif choice == '4': print("Program bude ukončen."); break
        else: print("Neplatná volba.")
        input("\nStiskněte Enter pro návrat do hlavního menu...")

if __name__ == "__main__":
    main_menu()

key = generate_random_key()
text = "BYL_POZDNI_VECER_PRVNI_MAJ_VECERNI_MAJ_BYL_LASKY_CAS"
encrypted = substitute_encrypt(text, key)
decrypted = substitute_decrypt(encrypted, key)
print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
print("Debug: Starting analysis...")
print("Encrypted text:", encrypted)

from MH_decipher.kryptolib import score_by_dictionary

# Pokud není WORDLIST_SET definován, načti jej ze souboru
if 'WORDLIST_SET' not in globals():
    try:
        with open("wordlist.txt", encoding="utf-8") as f:
            WORDLIST_SET = set(word.strip().upper() for word in f)
    except FileNotFoundError:
        print("❌ Soubor 'wordlist.txt' nebyl nalezen. Ujistěte se, že existuje ve správném adresáři.")
        WORDLIST_SET = set()  # Inicializace prázdné množiny jako fallback

# Pokud není all_results definován, inicializuj prázdný seznam (nebo načti výsledky)
if 'all_results' not in globals():
    all_results = []

# Debugging: Print all_results
print("Debug: all_results =", all_results)

# Kontrola, zda jsou k dispozici výsledky pro analýzu
if all_results:
    # Najdi nejlepšího kandidáta na základě skóre
    best_candidate = max(all_results, key=lambda r: score_by_dictionary(r['plaintext'], WORDLIST_SET))
    print("===== ANALÝZA DOKONČENA =====")
    print(f"\n🔓 Nalezený klíč: {best_candidate['key']}")
    print(f"📄 Dešifrovaný text: {best_candidate['plaintext']}")
    print(f"📈 Skóre: {float(best_candidate['score']):.2f}")
else:
    print("❌ Nebyly nalezeny žádné výsledky pro analýzu. Ujistěte se, že 'all_results' obsahuje data.")