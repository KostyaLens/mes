import java.util.Scanner;

public class VigenereCipher {

    private static final String RUSSIAN_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    private static final String ENGLISH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static String encrypt(String text, String key, String alphabet) {
        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int keyIndex = 0;
        int alphabetLength = alphabet.length();

        for (char c : text.toCharArray()) {
            int charIndex = alphabet.indexOf(Character.toUpperCase(c));
            boolean isUpper = Character.isUpperCase(c);
            int shift = alphabet.indexOf(key.charAt(keyIndex));
            char newChar = alphabet.charAt((charIndex + shift) % alphabetLength);
            result.append(isUpper ? newChar : Character.toLowerCase(newChar));
            keyIndex = (keyIndex + 1) % key.length();
        }
        return result.toString();
    }

    public static String decrypt(String text, String key, String alphabet) {
        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int keyIndex = 0;
        int alphabetLength = alphabet.length();

        for (char c : text.toCharArray()) {
            int charIndex = alphabet.indexOf(Character.toUpperCase(c));
            boolean isUpper = Character.isUpperCase(c);
            int shift = alphabet.indexOf(key.charAt(keyIndex));
            char newChar = alphabet.charAt((charIndex - shift + alphabetLength) % alphabetLength);
            result.append(isUpper ? newChar : Character.toLowerCase(newChar));
            keyIndex = (keyIndex + 1) % key.length();
        }
        return result.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Выберите язык алфавита: ");
        System.out.println("1. Русский");
        System.out.println("2. Английский");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Очистка буфера

        String alphabet = choice == 1 ? RUSSIAN_ALPHABET : ENGLISH_ALPHABET;

        System.out.println("Введите текст: ");
        String text = scanner.nextLine();

        System.out.println("Введите ключ: ");
        String key = scanner.nextLine();

        String encrypted = encrypt(text, key, alphabet);
        System.out.println("Зашифрованный текст: " + encrypted);

        String decrypted = decrypt(encrypted, key, alphabet);
        System.out.println("Расшифрованный текст: " + decrypted);

        scanner.close();
    }
}
