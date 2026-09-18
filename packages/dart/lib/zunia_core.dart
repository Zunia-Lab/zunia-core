/// High-level Dart API over the Zunia native kernel.
///
/// Native libraries are downloaded from a pinned GitHub Release tag by mobile CI
/// (`scripts/fetch-native.sh` in zunia-mobile). This package only declares the FFI surface.
///
/// Two groups of calls. Key handling — [ZuniaCore.generateMnemonic], [ZuniaCore.sealKeyring],
/// [ZuniaCore.openKeyring], [ZuniaCore.deriveAddress] — and the Cosmos transaction surface:
/// [ZuniaCore.buildSignBytes] and [ZuniaCore.assembleTxRaw] for a host that signs elsewhere,
/// [ZuniaCore.buildSimulateTx] for a gas estimate, [ZuniaCore.previewTx] for the approval
/// screen, and [ZuniaCore.signTx] when the app holds the mnemonic itself.
///
/// The transaction calls take every message type the kernel can encode — send, delegate,
/// undelegate, redelegate, withdraw rewards, vote, IBC transfer and contract execution — as the
/// same `[{ typeUrl, value }]` payload `@zunialab/interchain` emits. Nothing is encoded in
/// Dart: the bytes come from the Rust encoders that are pinned against CosmJS byte for byte.
library;

export 'src/zunia_core.dart';
