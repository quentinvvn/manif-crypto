import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'wordlist_fr.dart';

/// Pourquoi une phrase n'a pas pu être lue.
enum RecoveryPhraseError {
  /// Il faut exactement 24 mots.
  wordCount,

  /// Un mot n'appartient pas à la liste.
  unknownWord,

  /// Tous les mots existent mais la phrase est incohérente (faute de frappe,
  /// mots inversés) : la somme de contrôle ne correspond pas.
  checksum,
}

class RecoveryPhraseException implements Exception {
  const RecoveryPhraseException(this.error, {this.position, this.word});

  final RecoveryPhraseError error;

  /// Position (à partir de 1) du mot inconnu.
  final int? position;
  final String? word;

  @override
  String toString() => 'RecoveryPhraseException($error, position: $position)';
}

/// Phrase de récupération de 24 mots, au format BIP39 (liste française).
///
/// 256 bits d'aléa + 8 bits de somme de contrôle (SHA-256), découpés en
/// 24 groupes de 11 bits. La saisie est tolérante : majuscules, accents
/// absents et espaces multiples sont acceptés, et les 4 premières lettres
/// d'un mot suffisent (elles sont uniques dans la liste).
abstract final class RecoveryPhrase {
  static const wordCount = 24;
  static const entropyLength = 32;

  static final Map<String, int> _byWord = {
    for (var i = 0; i < bip39French.length; i++) _fold(bip39French[i]): i,
  };

  static final Map<String, int> _byPrefix = {
    for (var i = 0; i < bip39French.length; i++)
      _fold(bip39French[i]).substring(0, 4): i,
  };

  /// 32 octets → 24 mots.
  static Future<List<String>> encode(List<int> entropy) async {
    if (entropy.length != entropyLength) {
      throw ArgumentError('L\'aléa doit faire $entropyLength octets');
    }
    final checksum = (await Sha256().hash(entropy)).bytes.first;
    final bits = StringBuffer();
    for (final byte in [...entropy, checksum]) {
      bits.write(byte.toRadixString(2).padLeft(8, '0'));
    }
    final s = bits.toString();
    return [
      for (var i = 0; i < wordCount; i++)
        bip39French[int.parse(s.substring(i * 11, i * 11 + 11), radix: 2)],
    ];
  }

  /// Texte saisi → 32 octets. Lève [RecoveryPhraseException].
  static Future<Uint8List> decode(String input) async {
    final words = input
        .trim()
        .split(RegExp(r'[\s,;]+'))
        .where((w) => w.isNotEmpty)
        .toList();
    if (words.length != wordCount) {
      throw const RecoveryPhraseException(RecoveryPhraseError.wordCount);
    }

    final bits = StringBuffer();
    for (var i = 0; i < words.length; i++) {
      final index = indexOf(words[i]);
      if (index == null) {
        throw RecoveryPhraseException(
          RecoveryPhraseError.unknownWord,
          position: i + 1,
          word: words[i],
        );
      }
      bits.write(index.toRadixString(2).padLeft(11, '0'));
    }

    final s = bits.toString();
    final entropy = Uint8List(entropyLength);
    for (var i = 0; i < entropyLength; i++) {
      entropy[i] = int.parse(s.substring(i * 8, i * 8 + 8), radix: 2);
    }
    final checksum = int.parse(s.substring(256, 264), radix: 2);
    final expected = (await Sha256().hash(entropy)).bytes.first;
    if (checksum != expected) {
      throw const RecoveryPhraseException(RecoveryPhraseError.checksum);
    }
    return entropy;
  }

  /// Position d'un mot dans la liste, ou null. Tolère casse, accents absents
  /// et abréviation à 4 lettres ou plus.
  static int? indexOf(String word) {
    final folded = _fold(word);
    final exact = _byWord[folded];
    if (exact != null) return exact;
    if (folded.length < 4) return null;
    final candidate = _byPrefix[folded.substring(0, 4)];
    if (candidate == null) return null;
    return _fold(bip39French[candidate]).startsWith(folded) ? candidate : null;
  }

  /// Minuscules sans accents.
  static String _fold(String word) {
    final out = StringBuffer();
    for (final rune in word.toLowerCase().runes) {
      // Accents combinants (forme décomposée) : ignorés.
      if (rune >= 0x0300 && rune <= 0x036f) continue;
      out.write(_accents[rune] ?? String.fromCharCode(rune));
    }
    return out.toString();
  }

  static const Map<int, String> _accents = {
    0xe0: 'a', 0xe2: 'a', 0xe4: 'a', // à â ä
    0xe9: 'e', 0xe8: 'e', 0xea: 'e', 0xeb: 'e', // é è ê ë
    0xee: 'i', 0xef: 'i', // î ï
    0xf4: 'o', 0xf6: 'o', // ô ö
    0xf9: 'u', 0xfb: 'u', 0xfc: 'u', // ù û ü
    0xe7: 'c', // ç
  };
}
