# kryptolib.py

import random
import math
import numpy as np
import unicodedata
from collections import defaultdict

# --- Globální proměnné ---
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"

# --- Pomocné a základní funkce ---

def generate_random_key():
    """Vygeneruje a vrátí náhodný platný klíč pro substituci."""
    alphabet_list = list(alphabet)
    random.shuffle(alphabet_list)
    return "".join(alphabet_list)

def substitute_encrypt(plaintext, key):
    """Zašifruje text pomocí substituční šifry."""
    mapping = {alphabet[i]: key[i] for i in range(len(alphabet))}
    return "".join([mapping.get(char, char) for char in plaintext])

def substitute_decrypt(ciphertext, key):
    """Dešifruje text zašifrovaný substituční šifrou."""
    reverse_mapping = {key[i]: alphabet[i] for i in range(len(alphabet))}
    return "".join([reverse_mapping.get(char, char) for char in ciphertext])

def score_by_dictionary(text, wordlist_set):
    """Ohodnotí text podle toho, kolik platných slov ze slovníku obsahuje."""
    score = 0
    words = text.split('_')  # rozdělíme podle podtržítek
    for word in words:
        word_to_compare = word.lower()  # převedeme na malá písmena
        if word_to_compare in wordlist_set:
            score += len(word_to_compare) ** 2  # přičteme body podle délky slova
    return score

# --- Funkce pro práci s n-gramy ---

def get_ngrams(text, n):
    """Vrátí seznam n-gramů (např. bigramy nebo trigramy)."""
    return [text[i:i+n] for i in range(len(text) - n + 1)]

def create_ngram_log_prob_model(text, n):
    """Vytvoří model pravděpodobností pro n-gramy jako slovník log pravděpodobností."""
    counts = defaultdict(int)
    for ngram in get_ngrams(text, n):
        counts[ngram] += 1

    total_count = sum(counts.values())
    default_log_prob = math.log(0.01 / total_count)  # hodně malé číslo pro nevyskytující se n-gramy

    log_probs = defaultdict(lambda: default_log_prob)
    for ngram, count in counts.items():
        log_probs[ngram] = math.log(count / total_count)

    return log_probs

# --- Hybridní skórování (kombinuje bigramy a trigramy) ---

def plausibility_hybrid(text, bigram_model_np, trigram_model_dict, char_to_index):
    """Vrací skóre textu na základě kombinace bigramové a trigramové pravděpodobnosti."""
    if len(text) < 3:
        return -np.inf  # příliš krátký text

    # --- Bigramová část (rychlé počítání pomocí NumPy) ---
    n = len(char_to_index)
    tm_obs_np = np.ones((n, n), dtype=np.int32)  # matice výskytů
    for i in range(len(text) - 1):
        try:
            idx1, idx2 = char_to_index[text[i]], char_to_index[text[i+1]]
            tm_obs_np[idx1, idx2] += 1
        except KeyError:
            continue

    bigram_score = (np.log(bigram_model_np) * tm_obs_np).sum()

    # --- Trigramová část ---
    trigram_score = 0
    for trigram in get_ngrams(text, 3):
        trigram_score += trigram_model_dict[trigram]

    # --- Kombinované skóre ---
    return (0.4 * bigram_score) + (0.6 * trigram_score)  # trigramy mají větší váhu

# --- Funkce na prolomení šifry ---

def prolom_substitute_hybrid(text, bigram_model_np, trigram_model_dict, iter_count):
    """Metoda na prolomení šifry pomocí Metropolis-Hastings algoritmu a hybridního skórování."""
    alphabet_list = list(alphabet)
    char_to_index = {char: i for i, char in enumerate(alphabet)}

    current_key = generate_random_key()
    decrypted_current = substitute_decrypt(text, current_key)
    p_current = plausibility_hybrid(decrypted_current, bigram_model_np, trigram_model_dict, char_to_index)

    best_key, best_p = current_key, p_current

    for i in range(1, iter_count + 1):
        candidate_key_list = list(current_key)
        idx1, idx2 = random.sample(range(len(alphabet_list)), 2)  # prohodíme dva znaky v klíči
        candidate_key_list[idx1], candidate_key_list[idx2] = candidate_key_list[idx2], candidate_key_list[idx1]
        candidate_key = "".join(candidate_key_list)

        decrypted_candidate = substitute_decrypt(text, candidate_key)
        p_candidate = plausibility_hybrid(decrypted_candidate, bigram_model_np, trigram_model_dict, char_to_index)

        if p_candidate > p_current or random.random() < math.exp(p_candidate - p_current):
            current_key, p_current = candidate_key, p_candidate  # přijmeme nový klíč

        if p_current > best_p:
            best_p, best_key = p_current, current_key  # aktualizujeme nejlepší výsledek

        if i % 1000 == 0:
            print(f"\rIterace: {i}/{iter_count}, Nejlepší skóre: {best_p:.2f}", end="")

    print()
    best_decrypted_text = substitute_decrypt(text, best_key)
    return (best_key, best_decrypted_text, best_p)
