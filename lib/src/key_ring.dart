import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'recovery_phrase.dart';

/// Toutes les clés d'un utilisateur, dérivées d'une seule racine de
/// 32 octets générée sur le téléphone.
///
/// La racine s'écrit sous forme de phrase de 24 mots : c'est la seule
/// sauvegarde. Le serveur ne reçoit jamais la racine ni les clés secrètes,
/// seulement une empreinte de contrôle ([keyCheck]) et la clé publique
/// ([identityPublicKey]).
///
/// Dérivation : HKDF-SHA256(racine, sel = « manif/root/v1 »,
/// info = « manif/v1/<usage> »). Les sous-clés sont indépendantes : en
/// connaître une ne révèle rien des autres ni de la racine.
class KeyRing {
  KeyRing._(List<int> root) : _root = Uint8List.fromList(root);

  /// Nouvelle racine aléatoire.
  factory KeyRing.generate() => KeyRing._(randomBytes(RecoveryPhrase.entropyLength));

  /// Racine relue depuis le stockage sécurisé de l'appareil.
  factory KeyRing.fromRoot(List<int> root) {
    if (root.length != RecoveryPhrase.entropyLength) {
      throw ArgumentError('La racine doit faire ${RecoveryPhrase.entropyLength} octets');
    }
    return KeyRing._(root);
  }

  /// Racine retrouvée à partir de la phrase de récupération.
  static Future<KeyRing> fromPhrase(String phrase) async =>
      KeyRing._(await RecoveryPhrase.decode(phrase));

  static const _salt = 'manif/root/v1';

  final Uint8List _root;

  /// Copie de la racine, pour la conserver dans le Keystore.
  Uint8List get root => Uint8List.fromList(_root);

  Future<List<String>> phrase() => RecoveryPhrase.encode(_root);

  /// Chiffre les clés des originaux vidéo (coffre).
  Future<SecretKey> vaultKey() => _derive('vault');

  /// Chiffre les dossiers d'abus (faits, témoins, RIO).
  Future<SecretKey> caseKey() => _derive('case');

  /// Empreinte publiable : permet de vérifier qu'une phrase saisie est la
  /// bonne pour ce compte, sans rien révéler des clés.
  Future<Uint8List> keyCheck() async =>
      Uint8List.fromList(await (await _derive('key-check')).extractBytes());

  /// Paire de clés X25519, pour recevoir des documents partagés
  /// (avocat, association) aux tâches suivantes.
  Future<SimpleKeyPair> identityKeyPair() async {
    final seed = await (await _derive('identity')).extractBytes();
    return X25519().newKeyPairFromSeed(seed);
  }

  Future<Uint8List> identityPublicKey() async {
    final publicKey = await (await identityKeyPair()).extractPublicKey();
    return Uint8List.fromList(publicKey.bytes);
  }

  Future<SecretKey> _derive(String usage) => Hkdf(
        hmac: Hmac.sha256(),
        outputLength: 32,
      ).deriveKey(
        secretKey: SecretKey(_root),
        nonce: utf8.encode(_salt),
        info: utf8.encode('manif/v1/$usage'),
      );
}
