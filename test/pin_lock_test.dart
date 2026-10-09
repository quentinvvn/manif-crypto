import 'package:manif_crypto/manif_crypto.dart';
import 'package:test/test.dart';

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('PBKDF2-HMAC-SHA256 (vecteurs de référence)', () {
    test('password / salt / 1 itération', () async {
      final out = await PinLock.derive('password', 'salt'.codeUnits, 1);
      expect(hex(out),
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
    });

    test('password / salt / 2 itérations', () async {
      final out = await PinLock.derive('password', 'salt'.codeUnits, 2);
      expect(hex(out),
          'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43');
    });

    test('code à 6 chiffres / sel 0..15 / 1000 itérations', () async {
      final out =
          await PinLock.derive('123456', List<int>.generate(16, (i) => i), 1000);
      expect(hex(out),
          '6e3849111be8d3070634220666e93c55dbfd75e923f34d35716805464c0a7eaf');
    });
  });

  group('PinLock', () {
    // Peu d'itérations pour des tests rapides ; l'app utilise la valeur par défaut.
    final lock = PinLock(iterations: 1000);

    test('reconnaît le PIN, le code de panique et le reste', () async {
      final record = await lock.enroll(pin: '123456', panicCode: '654321');
      expect(await lock.check(record, '123456'), PinMatch.pin);
      expect(await lock.check(record, '654321'), PinMatch.panic);
      expect(await lock.check(record, '000000'), PinMatch.none);
      expect(await lock.check(record, ''), PinMatch.none);
    });

    test('refuse un code de panique identique au PIN', () {
      expect(lock.enroll(pin: '111111', panicCode: '111111'),
          throwsArgumentError);
    });

    test('le sel est aléatoire : deux inscriptions, deux empreintes', () async {
      final a = await lock.enroll(pin: '123456', panicCode: '654321');
      final b = await lock.enroll(pin: '123456', panicCode: '654321');
      expect(hex(a.salt), isNot(hex(b.salt)));
      expect(hex(a.pinHash), isNot(hex(b.pinHash)));
    });

    test('l\'enregistrement ne contient pas les codes en clair', () async {
      final record = await lock.enroll(pin: '123456', panicCode: '654321');
      final encoded = record.encode();
      expect(encoded, isNot(contains('123456')));
      expect(encoded, isNot(contains('654321')));
    });

    test('aller-retour JSON', () async {
      final record = await lock.enroll(pin: '123456', panicCode: '654321');
      final restored = PinRecord.decode(record.encode());
      expect(restored.iterations, 1000);
      expect(await lock.check(restored, '123456'), PinMatch.pin);
      expect(await lock.check(restored, '654321'), PinMatch.panic);
    });

    test('refuse une version d\'enregistrement inconnue', () {
      expect(() => PinRecord.fromJson({'v': 99}), throwsFormatException);
    });
  });

  test('la dérivation est remplaçable (calcul en arrière-plan)', () async {
    var calls = 0;
    final lock = PinLock(
      iterations: 1000,
      deriver: (secret, salt, iterations) {
        calls++;
        return PinLock.derive(secret, salt, iterations);
      },
    );
    final record = await lock.enroll(pin: '123456', panicCode: '654321');
    expect(await lock.check(record, '654321'), PinMatch.panic);
    expect(calls, 3);
  });

  group('constantTimeEquals', () {
    test('égalité et différences', () {
      expect(constantTimeEquals([1, 2, 3], [1, 2, 3]), isTrue);
      expect(constantTimeEquals([1, 2, 3], [1, 2, 4]), isFalse);
      expect(constantTimeEquals([1, 2, 3], [1, 2]), isFalse);
    });
  });

  test('randomBytes renvoie la longueur demandée', () {
    expect(randomBytes(16), hasLength(16));
  });
}
