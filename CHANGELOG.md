## 0.4.0

- `VideoCrypto` : clé de contenu par vidéo emballée par la clé du coffre ; segments chiffrés et liés à (vidéo, numéro).
- `HashChain` : chaîne d'empreintes SHA-256 des segments.

## 0.3.0

- Trousseau de clés (`KeyRing`) : racine de 32 octets, sous-clés HKDF-SHA256 (coffre, dossiers, identité X25519, empreinte de contrôle).
- Phrase de récupération de 24 mots, BIP39 liste française, saisie tolérante (accents, casse, 4 lettres).
- `Envelope` : AES-256-GCM avec en-tête versionné et contexte lié.

## 0.2.1

- Dérivation remplaçable (`PinLock(deriver: ...)`) pour calculer hors du fil de l'interface ; les deux empreintes de l'inscription sont calculées en parallèle.

## 0.2.0

- Verrou à deux codes : code PIN et code de panique (PBKDF2-HMAC-SHA256, comparaison en temps constant).

## 0.1.0

- Création du paquet.
