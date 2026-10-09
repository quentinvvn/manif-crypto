import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'envelope.dart';

/// Chiffrement des vidéos originales.
///
/// Chaque vidéo a sa propre clé de contenu (32 octets aléatoires). Cette clé
/// est emballée par la clé du coffre ([KeyRing.vaultKey]) et seule la
/// version emballée quitte le téléphone : on pourra un jour partager une
/// seule vidéo avec un avocat sans lui donner accès au reste du coffre.
///
/// Chaque segment est chiffré avec un contexte qui contient l'identifiant
/// de la vidéo et son numéro : le serveur ne peut ni échanger deux segments,
/// ni en déplacer un d'une vidéo à une autre, sans que le déchiffrement échoue.
abstract final class VideoCrypto {
  static SecretKey newContentKey() => SecretKey(randomBytes(32));

  static Future<Uint8List> wrapContentKey({
    required SecretKey vaultKey,
    required SecretKey contentKey,
    required String videoId,
  }) async =>
      Envelope.seal(vaultKey, await contentKey.extractBytes(),
          context: _keyContext(videoId));

  static Future<SecretKey> unwrapContentKey({
    required SecretKey vaultKey,
    required List<int> wrappedKey,
    required String videoId,
  }) async =>
      SecretKey(await Envelope.open(vaultKey, wrappedKey,
          context: _keyContext(videoId)));

  static Future<Uint8List> sealSegment({
    required SecretKey contentKey,
    required String videoId,
    required int index,
    required List<int> clear,
  }) =>
      Envelope.seal(contentKey, clear, context: _segmentContext(videoId, index));

  static Future<Uint8List> openSegment({
    required SecretKey contentKey,
    required String videoId,
    required int index,
    required List<int> sealed,
  }) =>
      Envelope.open(contentKey, sealed, context: _segmentContext(videoId, index));

  static List<int> _keyContext(String videoId) =>
      utf8.encode('manif/v1/video-key/$videoId');

  static List<int> _segmentContext(String videoId, int index) =>
      utf8.encode('manif/v1/segment/$videoId/$index');
}

/// Chaîne d'empreintes des segments, calculée sur les données en clair au
/// moment de la capture :
///
///   maillon(0) = 32 octets nuls
///   maillon(n) = SHA-256(maillon(n-1) ‖ SHA-256(segment n))
///
/// Le dernier maillon résume toute la vidéo : modifier, retirer ou réordonner
/// un seul segment le change. C'est lui qui sera horodaté (tâche 9).
abstract final class HashChain {
  static final Uint8List genesis = Uint8List(32);

  static Future<Uint8List> segmentHash(List<int> clear) async =>
      Uint8List.fromList((await Sha256().hash(clear)).bytes);

  static Future<Uint8List> link(List<int> previous, List<int> segmentHash) async =>
      Uint8List.fromList((await Sha256().hash([...previous, ...segmentHash])).bytes);

  /// Recalcule la chaîne complète à partir des empreintes des segments.
  static Future<Uint8List> fold(Iterable<List<int>> segmentHashes) async {
    var head = genesis;
    for (final h in segmentHashes) {
      head = await link(head, h);
    }
    return head;
  }
}
