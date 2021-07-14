import sys
import constants
import liblll
import utility
import ciphering
import deciphering
import attacking
import time
from tqdm import tqdm


def main():
    validation_message = utility.validate_initial_parameters()
    if validation_message != "":
        print(validation_message)
        sys.exit()

    print(constants.terminal_delimiter)
    print("\n" + "Hệ mật mã Knapsack - tấn công hệ mật mã sử dụng thuật toán LLL" )
    private_key_vector = utility.generate_super_increasing_vector()
    modulo = utility.determine_modulo_acc_to_random_key_vector(private_key_vector)
    multiplicative_to_mask = utility.determine_element_to_mask(modulo)

    public_key_vector = ciphering.generate_public_key_vector(private_key_vector, modulo, multiplicative_to_mask)
    print("\nMã khóa công khai được tạo từ hàm sinh khóa :  \n" +
          str(public_key_vector) + " \n" +
          "Sử dụng để mã hóa trong hệ mật mã knapsack\n")

    if not utility.random_text_test:
        input_text = utility.user_input("Nhập đoạn mã cần mã hóa : ", "")
        print("Nhập vào : " + str(input_text) + "\n")
    else:
        input_text = utility.generate_random_text(utility.length_of_random_text)
        print("Sinh ngẫu nhiên đoạn mã : " + str(input_text) + "\n")
        utility.press_enter_to_continue()

    bit_converted_text = utility.convert_text_to_bit(input_text)
    bit_grouped_sequences = utility.group_on_sequence(bit_converted_text, len(private_key_vector))
    print("Đang thực hiện mã hóa ...\n")

    ciphered_vector = ciphering.cipher_with_bit_sequences(public_key_vector, bit_grouped_sequences)
    print("Quá trình mã hóa kết thúc. Bạn vừa gửi 1 bản mã : \n" + str(ciphered_vector) + " \n" +
          "Bạn không thể giải mã nếu không có khóa bí mật." + "\n")

    input_text = utility.user_input("Bạn muốn tiếp tục với ? \n" +
                                    "Người nhận (giữ khóa bí mật): nhấn R, Kẻ tấn công: nhấn A",
                                    constants.regex_pattern_decipher_side_choice)

    if input_text.upper() == "R":
        decipher_as_receiver(ciphered_vector, modulo, multiplicative_to_mask, private_key_vector)
    elif input_text.upper() == "A":
        decipher_as_attacker(ciphered_vector, public_key_vector)

    print("\n" + "Kết thúc chương trình.")
    print(constants.terminal_delimiter)


def decipher_as_receiver(ciphered_vector, modulo, multiplicative_to_mask, private_key_vector):
    t = time.process_time()
    print("Quá trình giải mã chuẩn bị bắt đầu...\n")
    deciphered_vector = deciphering.decipher_vector_elements(ciphered_vector, modulo, multiplicative_to_mask)

    print("Đang thực hiện giải mã...\n")

    deciphered_bit_sequences = list()
    for i in tqdm(range(0, len(deciphered_vector)),ncols=60):
        deciphered_item = deciphered_vector[i]
        deciphered_bit_sequence = deciphering.deciphered_items_to_bit_sequence(
            constants.algorithm_back_tracking, private_key_vector, deciphered_item)
        deciphered_bit_sequences.append(deciphered_bit_sequence)
    print("\nQuá trình giải mã kết thúc.\n")

    deciphered_bits = ""
    for i in range(0, len(deciphered_bit_sequences)):
        deciphered_bits += deciphered_bit_sequences[i]
    deciphered_text = utility.convert_bit_to_text(deciphered_bits, len(private_key_vector))
    print("Thực hiện giải mã trong " + str(round(time.process_time() - t,2)) + " ms.\n\n" +
          "Bản rõ: " +
          str(deciphered_text))

    return True


def decipher_as_attacker(ciphered_vector, public_key_vector):
    t = time.process_time()

    print("Quá trình tấn công chuẩn bị bắt đầu...\n")
    print("Sử dụng thuật toán LLL basis lattice reduction ...\n")
    deciphered_bits = ""
    for i in tqdm(range(0, len(ciphered_vector)),ncols=60):
        ciphered_message = ciphered_vector[i]
        base_vector_list = attacking.create_base_vector_list(public_key_vector, ciphered_message)
        matrix_to_lll_reduction = liblll.create_matrix(base_vector_list)
        reduced_matrix = liblll.lll_reduction(matrix_to_lll_reduction)
        deciphered_bit_sequence = liblll.best_vect_knapsack(reduced_matrix)
        for i in range(len(deciphered_bit_sequence)):
            deciphered_bits += str(deciphered_bit_sequence[i])

    print("\nThuật toán Lattice reduction kết thúc.\n")
    deciphered_text = utility.convert_bit_to_text(deciphered_bits, len(public_key_vector))
    print("Thực hiện tấn công trong " + str(round(time.process_time() - t,2)) + " ms.\n\n" +
          "Bản rõ: " +
          str(deciphered_text))

    return True


if __name__ == "__main__":
    main()

