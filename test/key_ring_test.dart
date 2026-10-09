import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:manif_crypto/manif_crypto.dart';
import 'package:test/test.dart';

// Vecteurs calculés avec les bibliothèques de référence Python
// (mnemonic 0.21 pour BIP39, cryptography pour HKDF / X25519 / AES-GCM).

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

List<int> unhex(String s) => [
      for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
    ];

final rootVector = List<int>.generate(32, (i) => i);
const phraseVector =
    'abaisser agréable inductif agréable éligible achat bolide boucle amateur '
    'exister dérober bison abrasif justice écharpe inonder avancer piano '
    'adulte cobra papaye anonyme hangar tomate';

void main() {
  group('liste de mots', () {
    test('2048 mots, uniques même sans accents ni au-delà de 4 lettres', () {
      expect(bip39French, hasLength(2048));
      for (var i = 0; i < bip39French.length; i++) {
        expect(RecoveryPhrase.indexOf(bip39French[i]), i);
      }
    });
  });

  group('RecoveryPhrase (BIP39 français)', () {
    const vectors = {
      '0000000000000000000000000000000000000000000000000000000000000000':
          'abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser anaphore',
      '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f':
          'implorer visage sonnette voyage véloce pourpre volaille tribunal implorer visage sonnette voyage véloce pourpre volaille tribunal implorer visage sonnette voyage véloce pourpre volaille studieux',
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff':
          'zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie zoologie valable',
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f':
          phraseVector,
    };

    vectors.forEach((entropy, phrase) {
      test('encode et decode $entropy', () async {
        expect((await RecoveryPhrase.encode(unhex(entropy))).join(' '), phrase);
        expect(hex(await RecoveryPhrase.decode(phrase)), entropy);
      });
    });

    test('saisie tolérante : casse, accents absents, abréviations, espaces', () async {
      final sloppy = phraseVector
          .replaceAll('agréable', 'agre')
          .toUpperCase()
          .replaceAll('É', 'E')
          .replaceAll(' ', '   \n');
      expect(hex(await RecoveryPhrase.decode(sloppy)), hex(rootVector));
      expect(
          hex(await RecoveryPhrase.decode(phraseVector.replaceAll('agréable', 'AGREA'))),
          hex(rootVector));
    });

    test('accents en forme décomposée', () async {
      final decomposed = phraseVector.replaceAll('é', 'é');
      expect(hex(await RecoveryPhrase.decode(decomposed)), hex(rootVector));
    });

    test('mauvais nombre de mots', () {
      expect(
        RecoveryPhrase.decode('abaisser abaisser'),
        throwsA(isA<RecoveryPhraseException>()
            .having((e) => e.error, 'error', RecoveryPhraseError.wordCount)),
      );
    });

    test('mot inconnu, avec sa position', () {
      final words = phraseVector.split(' ')..[4] = 'chaussette';
      expect(
        RecoveryPhrase.decode(words.join(' ')),
        throwsA(isA<RecoveryPhraseException>()
            .having((e) => e.error, 'error', RecoveryPhraseError.unknownWord)
            .having((e) => e.position, 'position', 5)),
      );
    });

    test('trois lettres ne suffisent pas', () {
      expect(RecoveryPhrase.indexOf('aba'), isNull);
    });

    test('deux mots inversés : somme de contrôle fausse', () {
      final words = phraseVector.split(' ');
      final swapped = [...words]
        ..[0] = words[1]
        ..[1] = words[0];
      expect(
        RecoveryPhrase.decode(swapped.join(' ')),
        throwsA(isA<RecoveryPhraseException>()
            .having((e) => e.error, 'error', RecoveryPhraseError.checksum)),
      );
    });
  });

  group('KeyRing', () {
    final ring = KeyRing.fromRoot(rootVector);

    Future<String> keyHex(Future<SecretKey> key) async =>
        hex(await (await key).extractBytes());

    test('sous-clés HKDF-SHA256 conformes', () async {
      expect(await keyHex(ring.vaultKey()),
          '29b62290743e8e5480dfe669583773054a37f352363e58ce11c4d4b484db98c8');
      expect(await keyHex(ring.caseKey()),
          'f63dd72600db60970945aae3fc1b8999b5e161168928926857d366345a16b6a3');
      expect(hex(await ring.keyCheck()),
          '5b089fc29c4447766e50aecf02592a9c8e1e3f602aae7587999492249d187cad');
    });

    test('clé publique X25519 conforme', () async {
      expect(hex(await ring.identityPublicKey()),
          '66eed92bc0380fec038fe9b40ac84b78ace15d65719782e5b4faac9f3f39ed49');
    });

    test('la phrase redonne la même racine', () async {
      expect((await ring.phrase()).join(' '), phraseVector);
      final restored = await KeyRing.fromPhrase(phraseVector);
      expect(hex(restored.root), hex(rootVector));
    });

    test('deux trousseaux générés sont différents', () {
      expect(hex(KeyRing.generate().root), isNot(hex(KeyRing.generate().root)));
    });

    test('CRITÈRE : après « réinstallation », la phrase rouvre un original', () async {
      // Téléphone 1 : génère les clés, chiffre un original, note la phrase.
      final phone1 = KeyRing.generate();
      final phrase = (await phone1.phrase()).join(' ');
      final original = utf8.encode('segment vidéo original');
      final sealed = await Envelope.seal(await phone1.vaultKey(), original,
          context: utf8.encode('video:42'));

      // Téléphone réinstallé : seule la phrase est connue.
      final phone2 = await KeyRing.fromPhrase(phrase);
      expect(await Envelope.open(await phone2.vaultKey(), sealed,
              context: utf8.encode('video:42')),
          original);
      expect(hex(await phone2.keyCheck()), hex(await phone1.keyCheck()));

      // Une autre phrase ne l'ouvre pas.
      final stranger = KeyRing.generate();
      expect(Envelope.open(await stranger.vaultKey(), sealed,
              context: utf8.encode('video:42')),
          throwsA(isA<EnvelopeException>()));
    });
  });

  group('Envelope (AES-256-GCM)', () {
    final key = SecretKey(List<int>.generate(32, (i) => i));

    test('format conforme au vecteur de référence', () async {
      final sealed = await Envelope.seal(key, utf8.encode('bonjour manif'),
          context: utf8.encode('manif/test'),
          nonce: List<int>.generate(12, (i) => i));
      expect(hex(sealed),
          '01000102030405060708090a0b256db871aa90b03be020f9e2d79c3daa17ee0110e6ba4b1fa01507b78e');
    });

    test('aller-retour', () async {
      final sealed = await Envelope.seal(key, [1, 2, 3], context: [9]);
      expect(sealed, hasLength(3 + Envelope.overhead));
      expect(await Envelope.open(key, sealed, context: [9]), [1, 2, 3]);
    });

    test('un octet modifié est détecté', () async {
      final sealed = await Envelope.seal(key, [1, 2, 3]);
      sealed[sealed.length - 1] ^= 1;
      expect(Envelope.open(key, sealed), throwsA(isA<EnvelopeException>()));
    });

    test('un contexte différent est refusé', () async {
      final sealed = await Envelope.seal(key, [1, 2, 3], context: utf8.encode('video:1'));
      expect(Envelope.open(key, sealed, context: utf8.encode('video:2')),
          throwsA(isA<EnvelopeException>()));
    });

    test('version inconnue et données trop courtes', () async {
      final sealed = await Envelope.seal(key, [1]);
      sealed[0] = 2;
      expect(Envelope.open(key, sealed), throwsA(isA<EnvelopeException>()));
      expect(Envelope.open(key, [1, 2]), throwsA(isA<EnvelopeException>()));
    });

    test('deux chiffrements du même texte diffèrent (nonce aléatoire)', () async {
      final a = await Envelope.seal(key, [1, 2, 3]);
      final b = await Envelope.seal(key, [1, 2, 3]);
      expect(hex(a), isNot(hex(b)));
    });
  });
}
