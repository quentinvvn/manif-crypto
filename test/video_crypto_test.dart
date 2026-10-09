import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:manif_crypto/manif_crypto.dart';
import 'package:test/test.dart';

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('HashChain (vecteurs calculés avec hashlib)', () {
    final segments = [
      utf8.encode('segment 0'),
      utf8.encode('segment 1'),
      utf8.encode('segment 2'),
    ];

    test('empreintes des segments', () async {
      expect(hex(await HashChain.segmentHash(segments[0])),
          'c0dafc1f67ee55a51c4920215b92cd209abb62615bff1ae83fd62f8d310d1289');
    });

    test('maillons successifs', () async {
      const heads = [
        '5473f55958374a7c89a134e77b658d5c1aa8e2c6c8d5ca3d55d4e36dd0d5ce1d',
        'f35ae5d16651050c97efb65c57c6b0dfa42260110681f3cec967ce5f4049794c',
        '0152111f8e02fad22e6ff587f790f63686ad45def894872faf154caaaa7f0991',
      ];
      var head = HashChain.genesis;
      for (var i = 0; i < segments.length; i++) {
        head = await HashChain.link(head, await HashChain.segmentHash(segments[i]));
        expect(hex(head), heads[i]);
      }
    });

    test('réordonner deux segments change la chaîne', () async {
      final hashes = [for (final s in segments) await HashChain.segmentHash(s)];
      final swapped = [hashes[1], hashes[0], hashes[2]];
      expect(hex(await HashChain.fold(hashes)),
          isNot(hex(await HashChain.fold(swapped))));
    });
  });

  group('VideoCrypto', () {
    final vaultKey = SecretKey(List<int>.generate(32, (i) => i));
    const videoId = '11111111-2222-3333-4444-555555555555';

    test('clé de contenu : emballée, puis déballée', () async {
      final contentKey = VideoCrypto.newContentKey();
      final wrapped = await VideoCrypto.wrapContentKey(
          vaultKey: vaultKey, contentKey: contentKey, videoId: videoId);
      expect(hex(wrapped), isNot(contains(hex(await contentKey.extractBytes()))));
      final unwrapped = await VideoCrypto.unwrapContentKey(
          vaultKey: vaultKey, wrappedKey: wrapped, videoId: videoId);
      expect(await unwrapped.extractBytes(), await contentKey.extractBytes());
    });

    test('une clé emballée ne sert pas pour une autre vidéo', () async {
      final wrapped = await VideoCrypto.wrapContentKey(
          vaultKey: vaultKey, contentKey: VideoCrypto.newContentKey(), videoId: videoId);
      expect(
        VideoCrypto.unwrapContentKey(
            vaultKey: vaultKey, wrappedKey: wrapped, videoId: 'autre'),
        throwsA(isA<EnvelopeException>()),
      );
    });

    test('segment : aller-retour, et refus s\'il est déplacé', () async {
      final key = VideoCrypto.newContentKey();
      final clear = utf8.encode('images');
      final sealed = await VideoCrypto.sealSegment(
          contentKey: key, videoId: videoId, index: 3, clear: clear);
      expect(
          await VideoCrypto.openSegment(
              contentKey: key, videoId: videoId, index: 3, sealed: sealed),
          clear);
      expect(
          VideoCrypto.openSegment(
              contentKey: key, videoId: videoId, index: 4, sealed: sealed),
          throwsA(isA<EnvelopeException>()));
      expect(
          VideoCrypto.openSegment(
              contentKey: key, videoId: 'autre', index: 3, sealed: sealed),
          throwsA(isA<EnvelopeException>()));
    });
  });
}
