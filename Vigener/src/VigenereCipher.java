import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class VigenereCipher {

    public static String encrypt(String text, String key, String alphabet) {
        StringBuilder result = new StringBuilder();
        key = key.toLowerCase();
        int keyIndex = 0;
        int alphabetLength = alphabet.length();
        for (char c : text.toCharArray()) {
            if (!alphabet.contains(String.valueOf(c).toLowerCase())){
                result.append(c);
                continue;
            }
            int charIndex = alphabet.indexOf(Character.toLowerCase(c));
            boolean isUpper = Character.isUpperCase(c);
            int shift = alphabet.indexOf(key.charAt(keyIndex));
            char newChar = alphabet.charAt((charIndex + shift) % alphabetLength);
            result.append(isUpper ? newChar : Character.toLowerCase(newChar));
            keyIndex = (keyIndex + 1) % key.length();
        }
        return result.toString();
    }


    private static final String alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
    private static final int alphabetSize = alphabet.length();

    private static final Map<Character, Double> russianFreq = new HashMap<>() {{
        put('а', 0.0801); put('б', 0.0159); put('в', 0.0454); put('г', 0.0170); put('д', 0.0298);
        put('е', 0.0845); put('ё', 0.0004); put('ж', 0.0094); put('з', 0.0165); put('и', 0.0735);
        put('й', 0.0121); put('к', 0.0349); put('л', 0.0440); put('м', 0.0321); put('н', 0.0670);
        put('о', 0.1097); put('п', 0.0281); put('р', 0.0473); put('с', 0.0547); put('т', 0.0626);
        put('у', 0.0262); put('ф', 0.0026); put('х', 0.0097); put('ц', 0.0048); put('ч', 0.0144);
        put('ш', 0.0073); put('щ', 0.0036); put('ъ', 0.0004); put('ы', 0.0190); put('ь', 0.0174);
        put('э', 0.0032); put('ю', 0.0064); put('я', 0.0201);
    }};

    private static Map<Integer, Character> symlov = new HashMap<>();

    public static String cleanText(String text) {
        text = text.toLowerCase();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!alphabet.contains(String.valueOf(c))) {
                symlov.put(i, c);
            }
        }
        return text.replaceAll("[^" + alphabet + "]", "");
    }

    public static double indexOfCoincidence(String text) {
        int N = text.length();
        if (N <= 1) {
            return 0;
        }
        Map<Character, Long> frequencies = text.chars()
                .mapToObj(ch -> (char) ch)
                .collect(Collectors.groupingBy(ch -> ch, Collectors.counting()));

        double ic = frequencies.values().stream()
                .mapToDouble(f -> f * (f - 1))
                .sum() / (N * (N - 1.0));
        return ic;
    }

    public static Integer kasiskiExamination(String ciphertext, int minSeqLength, int maxKeyLength) {
        Map<String, List<Integer>> sequences = new HashMap<>();
        for (int i = 0; i <= ciphertext.length() - minSeqLength; i++) {
            String seq = ciphertext.substring(i, i + minSeqLength);
            sequences.computeIfAbsent(seq, k -> new ArrayList<>()).add(i);
        }

        Map<String, List<Integer>> repeatedSequences = sequences.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        List<Integer> spacings = new ArrayList<>();
        for (List<Integer> locs : repeatedSequences.values()) {
            for (int i = 0; i < locs.size() - 1; i++) {
                spacings.add(locs.get(i + 1) - locs.get(i));
            }
        }

        List<Integer> possibleKeyLengths = new ArrayList<>();
        for (int spacing : spacings) {
            for (int i = 2; i <= Math.min(spacing, maxKeyLength); i++) {
                if (spacing % i == 0) {
                    possibleKeyLengths.add(i);
                }
            }
        }

        if (possibleKeyLengths.isEmpty()) {
            return 0;
        }

        Map<Integer, Long> countMap = possibleKeyLengths.stream()
                .collect(Collectors.groupingBy(i -> i, Collectors.counting()));

        if (countMap.isEmpty()) {
            return 0;
        }

        long maxCount = Collections.max(countMap.values());
        List<Integer> candidates = countMap.entrySet().stream()
                .filter(entry -> entry.getValue() == maxCount)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        return Collections.max(candidates);
    }

    public static int estimateKeyLengthIc(String ciphertext, int maxKeyLength) {
        List<Map.Entry<Integer, Double>> ics = new ArrayList<>();
        for (int keyLength = 1; keyLength <= maxKeyLength; keyLength++) {
            List<Double> icValues = new ArrayList<>();
            for (int i = 0; i < keyLength; i++) {
                int finalKeyLength = keyLength;
                int finalI = i;
                String subsequence = IntStream.range(i, ciphertext.length())
                        .filter(n -> n % finalKeyLength == finalI)
                        .mapToObj(ciphertext::charAt)
                        .map(String::valueOf)
                        .collect(Collectors.joining());
                double ic = indexOfCoincidence(subsequence);
                icValues.add(ic);
            }
            double averageIc = icValues.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
            ics.add(new AbstractMap.SimpleEntry<>(keyLength, averageIc));
        }

        return ics.stream()
                .max(Comparator.comparingDouble(Map.Entry::getValue))
                .map(Map.Entry::getKey)
                .orElse(0);
    }

    public static int estimateKeyLengthCombined(String ciphertext, int maxKeyLength) {
        int keyLengthKasiski = kasiskiExamination(ciphertext, 4, maxKeyLength);
        if (keyLengthKasiski != 0 && 1 < keyLengthKasiski && keyLengthKasiski <= maxKeyLength) {
            return keyLengthKasiski;
        }

        int keyLengthIc = estimateKeyLengthIc(ciphertext, maxKeyLength);
        return keyLengthIc;
    }

    public static int calculateShift(String subtext, Map<Character, Double> russianFreq) {
        double minChiSquared = Double.MAX_VALUE;
        int bestShift = 0;
        for (int shift = 0; shift < alphabetSize; shift++) {
            StringBuilder shiftedSubtext = new StringBuilder();
            for (char c : subtext.toCharArray()) {
                int index = alphabet.indexOf(c);
                int shiftedIndex = (index - shift + alphabetSize) % alphabetSize;
                shiftedSubtext.append(alphabet.charAt(shiftedIndex));
            }
            Map<Character, Integer> frequencies = new HashMap<>();
            for (char c : shiftedSubtext.toString().toCharArray()) {
                frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
            }
            int total = shiftedSubtext.length();
            double chiSquared = 0;
            for (char letter : alphabet.toCharArray()) {
                int observed = frequencies.getOrDefault(letter, 0);
                double expected = total * russianFreq.getOrDefault(letter, 0.0);
                if (expected > 0) {
                    chiSquared += Math.pow(observed - expected, 2) / expected;
                }
            }
            if (chiSquared < minChiSquared) {
                minChiSquared = chiSquared;
                bestShift = shift;
            }
        }
        return bestShift;
    }

    public static String recoverKey(String ciphertext, int keyLength, Map<Character, Double> russianFreq) {
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < keyLength; i++) {
            StringBuilder subtext = new StringBuilder();
            for (int j = i; j < ciphertext.length(); j += keyLength) {
                subtext.append(ciphertext.charAt(j));
            }
            int shiftRecovered = calculateShift(subtext.toString(), russianFreq);
            char keyLetter = alphabet.charAt(shiftRecovered);
            key.append(keyLetter);
        }
        return key.toString();
    }

    public static String decrypt(String text, String key, String alphabet) {
        StringBuilder result = new StringBuilder();
        key = key.toLowerCase();
        int keyIndex = 0;
        int alphabetLength = alphabet.length();
        int i = 0;
        for (char c : text.toCharArray()) {
            int charIndex = alphabet.indexOf(Character.toLowerCase(c));
            boolean isUpper = Character.isUpperCase(c);
            int shift = alphabet.indexOf(key.charAt(keyIndex));
            char newChar = alphabet.charAt((charIndex - shift + alphabetLength) % alphabetLength);
            if (symlov.containsKey(i)) {
                result.append(symlov.get(i));
                i++;
                if (symlov.containsKey(i)) {
                    while (symlov.containsKey(i)) {
                        result.append(symlov.get(i));
                        i++;
                    }
                }
            }
            i++;
            result.append(isUpper ? newChar : Character.toLowerCase(newChar));
            keyIndex = (keyIndex + 1) % key.length();
        }
        return result.toString();
    }

    public static void main(String[] args) {

        String text = "Русские народные сказки воспитали не одно поколение детей, так как всегда отличались не просто интересным, но в первую очередь поучительным содержанием. Под эти сказки каждый вечер засыпали наши родители, бабушки и дедушки, и сегодня они остаются такими же актуальными. В этом разделе вы найдете большую коллекцию русских народных сказок, в которых сможете встретить и уже хорошо знакомых вам, полюбившихся персонажей, таких как Колобок, Илья Муромец, Елена премудрая, и возможно, откроете для себя новых героев.";

        String key = "наушники";

        String encrypted = encrypt(text, key, alphabet);
        System.out.println("Зашифрованный текст: " + encrypted);

        String cleanedCiphertext = cleanText(encrypted);
        int keyLength = estimateKeyLengthCombined(cleanedCiphertext, 15);
        key = recoverKey(cleanedCiphertext, keyLength, russianFreq);
        System.out.println(key);
        String plaintext = decrypt(cleanedCiphertext, key, alphabet);
        System.out.println("\nРасшифрованный текст:");
        System.out.println(plaintext);

    }
}
