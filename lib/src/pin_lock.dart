import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// Résultat de la saisie d'un code.
enum PinMatch {
  /// Le code PIN : ouvre la vraie session.
  pin,

  /// Le code de panique : ouvre une session vide et efface la vraie
  /// session de l'appareil.
  panic,

  /// Aucun des deux.
  none,
}

/// Empreintes du code PIN et du code de panique, à conserver dans le
/// stockage sécurisé de l'appareil (Keystore Android). Les codes eux-mêmes
/// ne sont jamais conservés.
///
/// Les deux empreintes partagent le même sel : une saisie ne demande donc
/// qu'un seul calcul, et vérifier le PIN ou le code de panique prend
/// exactement le même temps. Un observateur ne peut pas distinguer les deux.
class PinRecord {
  const PinRecord({
    required this.salt,
    required this.iterations,
    required this.pinHash,
    required this.panicHash,
  });

  final List<int> salt;
  final int iterations;
  final List<int> pinHash;
  final List<int> panicHash;

  Map<String, Object> toJson() => {
        'v': 1,
        'salt': base64Encode(salt),
        'iterations': iterations,
        'pin': base64Encode(pinHash),
        'panic': base64Encode(panicHash),
      };

  factory PinRecord.fromJson(Map<String, Object?> json) {
    if (json['v'] != 1) {
      throw const FormatException('Version d\'empreinte de PIN inconnue');
    }
    return PinRecord(
      salt: base64Decode(json['salt']! as String),
      iterations: json['iterations']! as int,
      pinHash: base64Decode(json['pin']! as String),
      panicHash: base64Decode(json['panic']! as String),
    );
  }

  String encode() => jsonEncode(toJson());

  static PinRecord decode(String source) =>
      PinRecord.fromJson(jsonDecode(source) as Map<String, Object?>);
}

/// Fonction de dérivation (secret, sel, itérations) → empreinte.
/// Remplaçable pour lancer le calcul hors du fil de l'interface.
typedef PinDeriver = Future<List<int>> Function(
  String secret,
  List<int> salt,
  int iterations,
);

/// Verrou de l'application à deux codes.
///
/// Limite assumée : un code à 6 chiffres n'a qu'un million de valeurs. La
/// dérivation lente (PBKDF2) gêne une attaque hors ligne mais ne l'empêche
/// pas ; la vraie protection est le stockage sécurisé de l'appareil et la
/// limitation des essais côté app.
class PinLock {
  PinLock({this.iterations = defaultIterations, PinDeriver? deriver})
      : _derive = deriver ?? derive;

  static const int defaultIterations = 100000;
  static const int saltLength = 16;
  static const int hashBits = 256;

  final int iterations;
  final PinDeriver _derive;

  /// Crée les empreintes. Le code de panique doit différer du PIN.
  Future<PinRecord> enroll({
    required String pin,
    required String panicCode,
  }) async {
    if (pin == panicCode) {
      throw ArgumentError('Le code de panique doit être différent du code PIN');
    }
    final salt = randomBytes(saltLength);
    final hashes = await Future.wait([
      _derive(pin, salt, iterations),
      _derive(panicCode, salt, iterations),
    ]);
    return PinRecord(
      salt: salt,
      iterations: iterations,
      pinHash: hashes[0],
      panicHash: hashes[1],
    );
  }

  /// Vérifie une saisie : un seul calcul, deux comparaisons en temps constant.
  Future<PinMatch> check(PinRecord record, String input) async {
    final hash = await _derive(input, record.salt, record.iterations);
    final isPin = constantTimeEquals(hash, record.pinHash);
    final isPanic = constantTimeEquals(hash, record.panicHash);
    if (isPin) return PinMatch.pin;
    if (isPanic) return PinMatch.panic;
    return PinMatch.none;
  }

  /// PBKDF2-HMAC-SHA256.
  static Future<List<int>> derive(
    String secret,
    List<int> salt,
    int iterations,
  ) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: iterations,
      bits: hashBits,
    );
    final key = await pbkdf2.deriveKeyFromPassword(
      password: secret,
      nonce: salt,
    );
    return key.extractBytes();
  }
}
