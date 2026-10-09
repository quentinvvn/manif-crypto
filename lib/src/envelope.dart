import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// Le déchiffrement a échoué : mauvaise clé, données modifiées, ou
/// contexte (associated data) différent.
class EnvelopeException implements Exception {
  const EnvelopeException(this.message);
  final String message;

  @override
  String toString() => 'EnvelopeException: $message';
}

/// Chiffrement authentifié AES-256-GCM avec un format versionné :
///
///   [version : 1 octet = 1][nonce : 12 octets][chiffré][tag : 16 octets]
///
/// Le contexte ([context], « associated data ») lie le chiffré à son usage
/// (par exemple l'identifiant d'une vidéo) : un chiffré déplacé ailleurs
/// ne se déchiffre pas.
abstract final class Envelope {
  static const version = 1;
  static const nonceLength = 12;
  static const tagLength = 16;
  static const overhead = 1 + nonceLength + tagLength;

  static final AesGcm _aes = AesGcm.with256bits();

  static Future<Uint8List> seal(
    SecretKey key,
    List<int> plaintext, {
    List<int> context = const [],
    List<int>? nonce,
  }) async {
    final box = await _aes.encrypt(
      plaintext,
      secretKey: key,
      nonce: nonce ?? randomBytes(nonceLength),
      aad: context,
    );
    return Uint8List.fromList([
      version,
      ...box.nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
  }

  static Future<Uint8List> open(
    SecretKey key,
    List<int> sealed, {
    List<int> context = const [],
  }) async {
    if (sealed.length < overhead) {
      throw const EnvelopeException('Données trop courtes');
    }
    if (sealed[0] != version) {
      throw const EnvelopeException('Version de format inconnue');
    }
    final nonce = sealed.sublist(1, 1 + nonceLength);
    final cipherText = sealed.sublist(1 + nonceLength, sealed.length - tagLength);
    final mac = Mac(sealed.sublist(sealed.length - tagLength));
    try {
      final clear = await _aes.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: mac),
        secretKey: key,
        aad: context,
      );
      return Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw const EnvelopeException('Clé incorrecte ou données modifiées');
    }
  }
}
