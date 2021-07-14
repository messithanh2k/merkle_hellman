import sys
import constants
import liblll
import utility
import ciphering
import deciphering
import attacking
import time


def main():
    validation_message = utility.validate_initial_parameters()
    if validation_message != "":
        print(validation_message)
        sys.exit()

    print(constants.terminal_delimiter)
    print("\n" + "The application started" )
    private_key_vector = utility.generate_super_increasing_vector()
    modulo = utility.determine_modulo_acc_to_random_key_vector(private_key_vector)
    multiplicative_to_mask = utility.determine_element_to_mask(modulo)

    public_key_vector = ciphering.generate_public_key_vector(private_key_vector, modulo, multiplicative_to_mask)
    print("\nReceiver's public key vector is: \n" +
          str(public_key_vector) + " \n" +
          "This vector will be used to cipher the message you text.\n")

    if not utility.random_text_test:
        input_text = utility.user_input("Please enter text to cipher", "")
        print("input text: " + str(input_text) + "\n")
    else:
        input_text = utility.generate_random_text(utility.length_of_random_text)
        print("generated input text: " + str(input_text) + "\n")
        utility.press_enter_to_continue()

    bit_converted_text = utility.convert_text_to_bit(input_text)
    bit_grouped_sequences = utility.group_on_sequence(bit_converted_text, len(private_key_vector))
    print("Ciphering part of the application is starting...\n")

    ciphered_vector = ciphering.cipher_with_bit_sequences(public_key_vector, bit_grouped_sequences)
    print("Ciphering part of the application is over. You just sent this cipher: \n" + str(ciphered_vector) + " \n" +
          "It can't be deciphered by anybody except the one who generated the public key vector." + "\n")

    input_text = utility.user_input("Which one do you want to continue as? \n" +
                                    "For receiver: R, For man-in-the-middle attacker: A",
                                    constants.regex_pattern_decipher_side_choice)

    if input_text.upper() == "R":
        decipher_as_receiver(ciphered_vector, modulo, multiplicative_to_mask, private_key_vector)
    elif input_text.upper() == "A":
        decipher_as_attacker(ciphered_vector, public_key_vector)

    print("\n" + "The application ended")
    print(constants.terminal_delimiter)


def decipher_as_receiver(ciphered_vector, modulo, multiplicative_to_mask, private_key_vector):
    t = time.process_time()
    print("\nAs a " + "RECEIVER" +
          " who generated public key, you own the modulo, multiplicative and private key vector. " +
          "\nThese were used to generate public key vector. \n" +
          "So, you can easily decipher the cipher text with using private key vector." + "\n")

    print("Deciphering part is about to start...\n")
    deciphered_vector = deciphering.decipher_vector_elements(ciphered_vector, modulo, multiplicative_to_mask)

    print("Knapsack solution algorithm is about to start...\n")

    deciphered_bit_sequences = list()
    for i in range(0, len(deciphered_vector)):
        deciphered_item = deciphered_vector[i]
        deciphered_bit_sequence = deciphering.deciphered_items_to_bit_sequence(
            constants.algorithm_back_tracking, private_key_vector, deciphered_item)
        deciphered_bit_sequences.append(deciphered_bit_sequence)
    print("Knapsack solution algorithm is over.\n")

    deciphered_bits = ""
    for i in range(0, len(deciphered_bit_sequences)):
        deciphered_bits += deciphered_bit_sequences[i]
    deciphered_text = utility.convert_bit_to_text(deciphered_bits, len(private_key_vector))
    print("Finished to decipher the text in " + str(time.process_time() - t) + " ms as a receiver.\n\n" +
          "Original text: " +
          str(deciphered_text))

    return True


def decipher_as_attacker(ciphered_vector, public_key_vector):
    t = time.process_time()
    print("\nAs an " + "ATTACKER" +
          ", you own the ciphered vector, public key vector. \n" +
          "So, you can decipher the cipher text with using lattice reduction." + "\n")

    print("Deciphering part is about to start...\n")
    print("LLL basis lattice reduction algorithm is about to start...\n")
    deciphered_bits = ""
    for i in range(0, len(ciphered_vector)):
        ciphered_message = ciphered_vector[i]
        base_vector_list = attacking.create_base_vector_list(public_key_vector, ciphered_message)
        matrix_to_lll_reduction = liblll.create_matrix(base_vector_list)
        reduced_matrix = liblll.lll_reduction(matrix_to_lll_reduction)
        deciphered_bit_sequence = liblll.best_vect_knapsack(reduced_matrix)
        for i in range(len(deciphered_bit_sequence)):
            deciphered_bits += str(deciphered_bit_sequence[i])

    print("Lattice reduction algorithm is over.\n")
    deciphered_text = utility.convert_bit_to_text(deciphered_bits, len(public_key_vector))
    print("Finished to decipher the text in " + str(time.process_time() - t) + " ms as an attacker.\n\n" +
          "Original text: " +
          str(deciphered_text))

    return True


if __name__ == "__main__":
    main()
