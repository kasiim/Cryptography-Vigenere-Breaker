# Author: Kaido Siimer
# Date: 09.10.2020
# Description: 

from string import ascii_uppercase
import itertools
import math

# Given ciphertext
ciphertext_string = "XSMLIWTBNEXTWGWEDZXGEWTXHFJXEEXZIGHEDDBZMOTREGEMWYTZVUCGZZMIDSIOIENWFQSYIGHMYBXVIDBBRKFVWIVWGBRKWWZMGYWMMGPBAEXEPXWSWLBIVDIKIRZBFSXTDTXIOBHVIEZXEXUCLXSCMOIRXIBRPJJRXLPQKVEEQHREWILWIDAFIREWYXLPLTRKPZLSJMIMXPPIGHFJBAIMCAXPJTVMIVPAMVEEPXVXSMRHMDKHZICILSYYLKIEDWGXSCCGEALGUCVPIEMDTVZXLLBPLEEQMQEVMLWIYAXJSCBAIQEWWSHPXXRHDWGALLBBXATTEQEVMLIRDMYSVZBAIVDBHHSLVWXLLBTPPZNMLIZBAIVDKTRRZBBGIEPBWXZWXZIYIJYMEMUVEGMLSPOQXVQLGIVIQMKXSCCGVEEPXVXSIGLICWBGEWTRFYEXHMRETXWWWGWMIEZRMRRBHWXPUMLIZVVSQTVZXMOMTPPMGAMQDMEJXSCLAINWNPHTUTKMYMPMXSWNXGZVMVEOQVXMZVTGMCKNQWEIGGITVPLMNPTRECUREPWWYALZAXQIXJXVWLZXFVLDXJPPMLEXEWIWTPMWFIQWKIXSMXRIXGFEOPATQSGMBJXSMLSPOQXVWCMTPPJIKIFCIOIXSMGXLTALYVPTRMWYBMLIZCMGSXMTRCZNMLIXETRXPLXEGSEHYPOPTZIAZXJICZXHXSIMEPWAMEROIGHJTOAXASIMAISIOILPZXXLPVBWENILIMYEAMGSBAIMYBXVENBBSRZNFERJQGHMGQWYEWTRVEEQHREWLXGMDQHRQLSBRKAZHGIDAXWSYMIVSNMLWTPZLSPOQXVTCWWYGPATRSFBVSQPQGXIYLXHFJVHSRPUHWXLZFMIDBKCXZIOSMOBAMWAZHFPPUCYWEILGSCBXDHTLLMRNMMLIJKTRXFANEPWGFEOPZXXVPIMTLJABGEWTRMQAWLWMMTXXLPGFEOPQMIGZVHQMNIEPCTUISWDQUPIEPXCWSWHXHPAXVXPZLXLPVLXEYLBRKLVWJMRPMMRRQLIENPLSPOQXVWTVWMZTLNEPWGKEXTWGEPNWNVWPWYEGEQHREQBXVEWTUIGLCLIXSMVSWEWYVYYVBRKTALYVPBHFILBEIEDBTWLTOAEWEPXGSDBHJWEIRMRR"

# Additional ciphertext for testing
# ciphertext_string1 = "QRRDUETOEJSNOOCFNUBRQXAEFDRWEYPPZFNGQLNUFBSMSPRFFCHSEZPBVMEPPMCVTNUIBOAAECBNMHOIPBTVPNGIOHHHVUAPDOZNOQBTRTAOVIYUIAEIFQLNZACIYFJCNMKRZBBBRQBNQBNVOTRSNNMBNUTRSYGIIFQOPLEGTIMFDQFVVDEEFMNJNFTMNMLRSAAELVHHGFRGIAAUHRBVRSATFSZBRGQHBOECSEPVRFPRJBSOVIYUFBSEIFRLEALVSRCUGDOZQRBNIFFSAPTUJNTBSNEEIFLBQMROTCMAGGOENPBXEEFDOZAAGPTBHBTTRESBGTPPRRTYFUEZPNPIICTOPJTTJVRTDRWEYPPRSSGIESSEREOZUOPVSGPMVAEAFAEMYRWEEZAFQEPUOSUHRQLNUFBSMCSEPVRFPRJBSQFSVHNREFEPMGIETSOHODHQTBQRBWIQFSRDUEJTLCYWVSGJFLJNTURHTTVOAAJNPSENTIAHLLIOFUIYFWBSLQJTFURNOSCBRROTZJNVNAYJSGJCQFSVHNVOVVUEFJNFQEPUIBOAAEMVUITBTRTSHQPYZCUBIABTGBCXTIGTEZCEQEEQDRLQTBHRNQHVDPEJMVUIIFSFJMCMISZTUFIZQLRNEAUAGJOAPFPPMCVTNUIBOAYMYVOTROSVWECSOGPCBMSFVCUBSGIEQPUOMEEBTPIEGUHNUHNTBEPUTITRODGPEAEEADRLQTRECBNMHOIPBTVPNVOTBUHRNAVOSGSENNAAEIGTSRBLVOGCSIZJTVWEFGAPJLVUAGFTUFCEFAGJOABNQTTBSATFOSDRLQTBHRNQHVDKRZSQFSCJTRBTVHHGMYVOTRHRNUEQNOOJLRGOENFNDTBSPEFCHSSBSAYTOCSOIJDRTHBPKFGOEIAEEWNSEZPDFJTFLELCONSDVTAFFPNSAGFIPQRBWIFJOAFDCDBGIAGPPROSGIEQPOEUOAPVRMLNZOHUSNODVONBWAGJVRTEATOETAAEIGTBNUTRSYPBVVUYRYPBTEFHPVPSGIAGBLYPWQFVRMOCFRFUOGSAQFBNUTRSYYJFRGOEBDQJTVPNNMHNSDJBRRGUADTVPNNMIGZ"

# http://inventwithpython.com/hacking/chapter20.html
english_distribution = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}

subscript_numbers = {
    0 : "\N{SUBSCRIPT ZERO}",
    1 : "\N{SUBSCRIPT ONE}",
    2 : "\N{SUBSCRIPT TWO}",
    3 : "\N{SUBSCRIPT THREE}",
    4 : "\N{SUBSCRIPT FOUR}",
    5 : "\N{SUBSCRIPT FIVE}",
    6 : "\N{SUBSCRIPT SIX}",
    7 : "\N{SUBSCRIPT SEVEN}",
    8 : "\N{SUBSCRIPT EIGHT}",
    9 : "\N{SUBSCRIPT NINE}"
    }

def get_letter_count_of_text(ciphertext_string):
    ciphertext = {}
    ciphertext['text'] = ciphertext_string
    ciphertext['letter_count'] = {}
    ciphertext['total_count_of_letters'] = len(ciphertext['text'])
    for letter in ascii_uppercase:
        ciphertext['letter_count'][letter] = ciphertext['text'].count(letter)

    return ciphertext

def calculate_index_of_coincidence(ciphertext):
    index_of_coincidence = 0
    for letter in ciphertext['letter_count'].keys():
        index_of_coincidence += (ciphertext['letter_count'][letter] * (ciphertext['letter_count'][letter] - 1)) / \
        (ciphertext['total_count_of_letters'] * (ciphertext['total_count_of_letters'] - 1))
    return index_of_coincidence

def calculate_mutual_index_of_coincdence(ciphertext_1, ciphertext_2):
    mutual_index_of_coincidence = 0
    for letter in ascii_uppercase:
        mutual_index_of_coincidence += (ciphertext_1['letter_count'][letter] * ciphertext_2['letter_count'][letter]) / \
        (ciphertext_1['total_count_of_letters'] * ciphertext_2['total_count_of_letters']) 

    return mutual_index_of_coincidence

def gcd(a, b):
    while (b):
        a, b = b, a % b
    return a

def gcd_of_list(list_of_numbers):
    try:
        calculated_gcd = gcd(list_of_numbers[0], list_of_numbers[1])
        for number in list_of_numbers[2:]:
            calculated_gcd = gcd(calculated_gcd, number)
        return calculated_gcd
    except IndexError:
        print("List is empty")
        return 1


def keylength_check_by_ioc(key_length):
    slices = [ciphertext['text'][i::key_length] for i in range(key_length)]

    key_length_check = True

    sliced_ciphertexts = []

    for index, sliced_ciphertext in enumerate(slices):
        sliced_ciphertext = get_letter_count_of_text(sliced_ciphertext)
        sliced_ciphertext['ioc'] = calculate_index_of_coincidence(sliced_ciphertext)
        # print(sliced_ciphertext['ioc'])
        sliced_ciphertext['index'] = index
        sliced_ciphertexts.append(sliced_ciphertext)

    for sliced_ciphertext in sliced_ciphertexts:
        if sliced_ciphertext['ioc'] < 0.055:
            key_length_check = False

    # print("Result of keylength check is:", key_length_check)

    return sliced_ciphertexts, key_length_check

def generate_all_possible_keys(key_indexes):
    possible_keys = []
    # Generate all possible keys
    for shift in range(0, 26):
        generated_key = ''
        for letter_index in key_indexes:
            generated_key += ascii_uppercase[(letter_index + shift) % 26]
        possible_keys.append(generated_key)

    return possible_keys

def solve_key_difference_system(key_differences, key_length):
    first_key = 0

    key_indexes = [first_key]

    relation_check_state = True

    # Pick first condition for each key
    if key_length - 1 == len(key_differences.keys()):
        for key_to_construct in key_differences.keys():
            key_indexes.append(key_differences[key_to_construct][0]['shift_value'])

            del key_differences[key_to_construct][0]

        # Control other conditions
        for key in key_differences.keys():
            for relation in key_differences[key]:
                relation_check = (key_indexes[relation['key_index']] + relation['shift_value']) % 26 == key_indexes[key]
                if relation_check == False:
                    relation_check_state = False
                    print(key, relation, relation_check)
    
    else:
        relation_check_state = False


    return key_indexes, relation_check_state

def decrypt_ciphertext_by_shift(ciphertext_string, key: int):
    decrypted_ciphertext_string = ''
    for letter in ciphertext_string:
        decrypted_ciphertext_string += ascii_uppercase[(ascii_uppercase.index(letter) + key) % 26]
    decrypted_ciphertext = get_letter_count_of_text(decrypted_ciphertext_string)

    return decrypted_ciphertext

def decrypt_vigenere(ciphertext_string, key):
    decrypted_plaintext = {}
    decrypted_text_string = ''
    for letter_index, letter in enumerate(ciphertext_string):
        decrypted_text_string += ascii_uppercase[(ascii_uppercase.index(letter) - ascii_uppercase.index(key[letter_index % len(key)])) % 26]

    decrypted_plaintext = get_letter_count_of_text(decrypted_text_string)

    return decrypted_plaintext

def calculate_letter_distributions(text):
    text['letter_distribution'] = {}
    for letter in text['letter_count'].keys():
        text['letter_distribution'][letter] = (text['letter_count'][letter] / text['total_count_of_letters']) * 100


def calculate_error_between_english_and_plaintext(plaintext, english_distribution):
    cummulative_error = 0
    for letter in english_distribution.keys():
        cummulative_error += (english_distribution[letter] - plaintext['letter_distribution'][letter]) * (english_distribution[letter] - plaintext['letter_distribution'][letter])
    
    return math.sqrt(cummulative_error)

def find_probable_key_length(ciphertext, trigram_to_search):
    start_index = 0
    count = 0

    found_trigrams_at_indexes = []

    for i in range(len(ciphertext['text'])):
        found_at_index = ciphertext['text'].find(trigram_to_search, start_index)
        if (found_at_index != -1):
            found_trigrams_at_indexes.append(found_at_index)
            start_index = found_at_index + 1
            count += 1
            found_at_index = 0
        
    # Key length can be guessed from greatest common divider of trigram starting positions
    ciphertext['probable_key_length'] = gcd_of_list(found_trigrams_at_indexes)
    # print("Key is probably of length:", ciphertext['probable_key_length'])

def find_trigrams(ciphertext):
    from operator import itemgetter
    found_trigrams = {}
    for i in range(len(ciphertext['text'])):
        try:
            found_trigrams[ciphertext['text'][i:i+3]] += 1
        except KeyError:
            found_trigrams[ciphertext['text'][i:i+3]] = 1

        # print(ciphertext['text'][i:i+3])

    sorted_dict = dict(sorted(found_trigrams.items(), reverse=True, key=lambda item: item[1]))

    suitable_trigrams = []
    for key in sorted_dict.keys():
        if sorted_dict[key] >= 3:
            # print(sorted_dict[key])
            suitable_trigrams.append(key)

    # print(suitable_trigrams)

    return suitable_trigrams

def int_to_subscript(integer):
    str_int = str(integer)
    str_to_return = ''
    
    for symbol in str_int:
        str_to_return += subscript_numbers[int(symbol)]

    return str_to_return

def find_key_differences(combinations_of_sliced_ciphertexts):
    mioc_of_combinations = []
    combination_indexes = []
    for index_of_pair, combination_of_two in enumerate(combinations_of_sliced_ciphertexts):
        combination_indexes.append((combination_of_two[0]['index'], combination_of_two[1]['index']))
        mioc_of_combinations.append([])
        # Calculate all mutual index of coincidences for each key for every pair and list them
        for key in range(26):
            decrypted_ciphertext = decrypt_ciphertext_by_shift(combination_of_two[1]['text'], key)
            mioc_of_combinations[index_of_pair].append(calculate_mutual_index_of_coincdence(combination_of_two[0], decrypted_ciphertext))

    key_differences = {}
    for pair_indexes, mioc_of_pairs in zip(combination_indexes, mioc_of_combinations):
        max_mioc = max(mioc_of_pairs)
        # If mutual index of coincidence is higher than 0.06 we can assume that key pair is good for selection
        if max_mioc > 0.055:
            index_of_max_mioc = mioc_of_pairs.index(max(mioc_of_pairs))

            # Calculate shift value from relation 
            shift_value = -index_of_max_mioc % 26

            # Show all MIOCs with good values and generate system dependent on that
            print(f"MIOC: {max_mioc} z{int_to_subscript(pair_indexes[0] + 1)} - z{int_to_subscript(pair_indexes[1] + 1)} = {index_of_max_mioc} (mod 26) => z{int_to_subscript(pair_indexes[1] + 1)} = z{int_to_subscript(pair_indexes[0] + 1)} + {shift_value} (mod 26)" )

            try: 
                key_differences[pair_indexes[1]].append(
                    {
                    'key_index' : pair_indexes[0],
                    'shift_value' : shift_value
                    }
                )
            except KeyError:
                key_differences[pair_indexes[1]] = []
                key_differences[pair_indexes[1]].append(
                    {
                    'key_index' : pair_indexes[0],
                    'shift_value' : shift_value
                    }
                )

    return key_differences

def decrypt_vigenere_with_all_keys_and_find_letter_distributions(list_of_possible_keys):
    letter_distribution_errors_for_keys = []

    for key in list_of_possible_keys:
        decrypted_plaintext = decrypt_vigenere(ciphertext_string, key)
        calculate_letter_distributions(decrypted_plaintext)
        distribution_error = calculate_error_between_english_and_plaintext(decrypted_plaintext, english_distribution)
        letter_distribution_errors_for_keys.append(distribution_error)

    return letter_distribution_errors_for_keys    

if __name__ == "__main__":
    # Step 1 decide what cipher probably is used
    # This can be done by looking letter distribution and index of coincidence
    # If index of coincidence is high (close to 0.07) we can assume monoalphabetic subsitution
    # Else if it is low (close to 0.0385) we can asume message is crypted polyalphabetic cipher
    # Note Vigenere cipher with key lenght 4 to 8 letters have usually IC of about 0.045 +- 0.05
    # Source: https://www.dcode.fr/index-coincidence

    print("Encrypted text:", ciphertext_string)

    ciphertext = get_letter_count_of_text(ciphertext_string)

    # plt.bar(*zip(*ciphertext['letter_count'].items()))

    ciphertext['ioc'] = calculate_index_of_coincidence(ciphertext)

    # Following a Vigenere encryption, 
    # #the message has a coincidence index which decreases between 
    # 0.05 and 0.04 depending on the length of the key,
    # it decreases towards 0.04 the longer the key is.
    print("Step 1:")
    if ciphertext['ioc'] < 0.05: 
        print("Calculated IOC:", ciphertext['ioc'], "Cipher is probably polyalphabetic")
    else:
        print("Calculated IOC:", ciphertext['ioc'], "Cipher is probably monoalphabetic")


    # Step 2 in this case IOC is around 0.04758 meaning Vigenere cipher is suitable
    # (Also we know that it is encrypted by Vigenere cipher)
    # So second step to breaking Vigenere cipher is to figure out key length
    # To figure out key length I use Kasiski examination

    # could be used to search for more letters than trigrams, but in my case it doesnt exist
    # trigram_to_search = ciphertext['text'][:3]
    print("Step 2:")
    trigrams_to_search = find_trigrams(ciphertext)

    possible_key_lengths = set()
    possible_sliced_ciphertexts = {}

    for trigram in trigrams_to_search:
        find_probable_key_length(ciphertext, trigram)
        # print(ciphertext['probable_key_length'])
    # Also to confirm that key is length I calculate IOC for each of the alphabets, if we have key
    # with length of five we use 5 alphabets
    # Slice ciphertext into five groups and check IOC of each one, if all IOC > 0.06 then it is probably the right length
        
        sliced_ciphertexts, key_ioc_check = keylength_check_by_ioc(ciphertext['probable_key_length'])
        if key_ioc_check:
            possible_key_lengths.add(ciphertext['probable_key_length'])
            possible_sliced_ciphertexts[ciphertext['probable_key_length']] = sliced_ciphertexts

    
    print('Possible key lengths are:', possible_key_lengths)
    # print(possible_sliced_ciphertexts)

    # Step 3 is to find differences of keys
    # To achive this it is needed to calculate mutual index of coincidence between pairs of different ciphertexts (sliced by keys)
    # In this case we get five different ciphertexts, from that we can find differences between keys by calculating mutual 
    # index of coinidence and selecting maximal value for each difference
    # from that we get system from which we can derive all other keys by one key.
    # This essencially makes polyalphabetic cipher act as monoalphabetic and we can break it like monoalphabetic cipher
    # In this case it will be monoalphabetic shift cipher
    print("Step 3:")

    for key_length in possible_key_lengths:
        combinations_of_sliced_ciphertexts = list(itertools.combinations(possible_sliced_ciphertexts[key_length], 2))

        # Generate all possible pairs of our keys in my case (5)

        key_differences = find_key_differences(combinations_of_sliced_ciphertexts)


        key_indexes, is_whole_system_solvable = solve_key_difference_system(key_differences, key_length)

        # print(key_indexes)
        # Step 4 from relations we calculated we can generate all possible keys by shifting through all possible shifts (25) of them
        if is_whole_system_solvable:
            list_of_possible_keys = generate_all_possible_keys(key_indexes)

            print("Possible list of keys:", list_of_possible_keys)

            # Step 5 decrypt ciphertext with all possible keys and find letter distributions for all plaintexts
            print("Step 5:")
            letter_distribution_errors_for_keys = decrypt_vigenere_with_all_keys_and_find_letter_distributions(list_of_possible_keys)
            print("Letter distribution errors vs english letter distribution", letter_distribution_errors_for_keys)


            # Step 6 check for text which resembles english and do additional check vs english letter distribution
            print("Step 6:")
            best_key = list_of_possible_keys[letter_distribution_errors_for_keys.index(min(letter_distribution_errors_for_keys))]
            solution_text = decrypt_vigenere(ciphertext_string, best_key)

            print("Most probable key based on english letter distribution check is:", best_key)
            print("Decrypted text:", solution_text['text'])
