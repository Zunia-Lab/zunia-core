import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// A failure reported by the native kernel, or by this wrapper before it got there.
///
/// The C ABI signals failure by returning a string prefixed `error: `, which is easy for a
/// caller to forget to check; a thrown exception is not. Never return the sentinel string to
/// application code — a wallet that broadcasts the word "error" is worse than one that crashes.
class ZuniaCoreException implements Exception {
  const ZuniaCoreException(this.message);

  final String message;

  @override
  String toString() => 'ZuniaCoreException: $message';
}

/// A Cosmos coin.
///
/// The amount is a decimal string, never an `int` or a `double`. Cosmos amounts are
/// arbitrary-precision integers: an 18-decimal token balance overflows a 64-bit int, and a
/// double loses precision above 2^53, which for such a token is about 0.009 of it — small
/// enough to look right on screen and wrong enough to fail on chain.
class ZuniaCoin {
  const ZuniaCoin({required this.denom, required this.amount});

  factory ZuniaCoin.fromJson(Map<String, dynamic> json) => ZuniaCoin(
        denom: json['denom'] as String,
        amount: json['amount'] as String,
      );

  final String denom;
  final String amount;

  Map<String, dynamic> toJson() => {'denom': denom, 'amount': amount};

  @override
  String toString() => '$amount$denom';
}

/// The transaction fee: what is paid, and the gas the transaction may use.
///
/// `gasLimit` has no default. A zero or absent gas limit is rejected by the kernel rather than
/// by the chain, because the chain's answer arrives after the user has signed and says "out of
/// gas", which names the wrong problem.
class ZuniaFee {
  const ZuniaFee({required this.amount, required this.gasLimit});

  factory ZuniaFee.fromJson(Map<String, dynamic> json) => ZuniaFee(
        amount: ((json['amount'] as List<dynamic>?) ?? const [])
            .map((e) => ZuniaCoin.fromJson(e as Map<String, dynamic>))
            .toList(growable: false),
        gasLimit: int.parse('${json['gas_limit']}'),
      );

  /// May be empty wherever the chain's minimum gas price is zero, which is the normal case on
  /// a devnet.
  final List<ZuniaCoin> amount;
  final int gasLimit;

  /// The wire shape the kernel parses: `gas_limit` as a string, because it is a `uint64`.
  Map<String, dynamic> toJson() => {
        'amount': amount.map((c) => c.toJson()).toList(growable: false),
        'gas_limit': gasLimit.toString(),
      };
}

/// Which of the two sign documents to produce.
///
/// Not defaulted anywhere it is passed. Direct and Amino are two different documents, not two
/// encodings of one: a Ledger signer requires Amino and a modern dApp expects Direct, and
/// signing the wrong one yields a signature that verifies against nothing, which the chain
/// reports as an opaque "unauthorized".
enum ZuniaSignMode {
  direct('direct'),
  amino('amino');

  const ZuniaSignMode(this.wire);

  /// The spelling the C ABI accepts.
  final String wire;

  static ZuniaSignMode fromWire(String value) => ZuniaSignMode.values.firstWhere(
        (mode) => mode.wire == value,
        orElse: () => throw ZuniaCoreException('unknown sign mode $value'),
      );
}

/// What the approval screen shows, computed from the transaction that will actually be signed.
///
/// [signBytesHash] is SHA-256 of the exact bytes [ZuniaCore.buildSignBytes] returns for the
/// same arguments, so the screen and the broadcast can be proven to describe one document. It
/// is mode-specific: a preview built for Direct does not describe the Amino document.
class ZuniaSigningPreview {
  const ZuniaSigningPreview({
    required this.chainId,
    required this.mode,
    required this.summaries,
    required this.msgs,
    required this.fee,
    required this.gasLimit,
    required this.memo,
    required this.spendsFunds,
    required this.counterparties,
    required this.signBytesHash,
  });

  factory ZuniaSigningPreview.fromJson(Map<String, dynamic> json) => ZuniaSigningPreview(
        chainId: json['chainId'] as String,
        mode: ZuniaSignMode.fromWire(json['mode'] as String),
        summaries: (json['summaries'] as List<dynamic>)
            .map((e) => e as String)
            .toList(growable: false),
        msgs: (json['msgs'] as List<dynamic>)
            .map((e) => (e as Map).cast<String, dynamic>())
            .toList(growable: false),
        fee: (json['fee'] as List<dynamic>)
            .map((e) => ZuniaCoin.fromJson((e as Map).cast<String, dynamic>()))
            .toList(growable: false),
        gasLimit: int.parse(json['gasLimit'] as String),
        memo: json['memo'] as String,
        spendsFunds: json['spendsFunds'] as bool,
        counterparties: (json['counterparties'] as List<dynamic>)
            .map((e) => e as String)
            .toList(growable: false),
        signBytesHash: json['signBytesHash'] as String,
      );

  /// One human-readable line per message, in order.
  final List<String> summaries;

  /// The messages as the kernel parsed them, which is not always what was sent: a field this
  /// build does not understand is dropped rather than signed, and showing the parsed form is
  /// what makes that visible instead of assumed.
  final List<Map<String, dynamic>> msgs;

  final String chainId;
  final ZuniaSignMode mode;
  final List<ZuniaCoin> fee;
  final int gasLimit;
  final String memo;

  /// True when at least one message moves funds out of the signer's account.
  final bool spendsFunds;

  final List<String> counterparties;
  final String signBytesHash;
}

typedef _StringFn = Pointer<Utf8> Function();
typedef _FreeFn = Void Function(Pointer<Utf8>);
typedef _GenMnemonicNative = Pointer<Utf8> Function(Uint32);
typedef _GenMnemonicDart = Pointer<Utf8> Function(int);
typedef _SealNative = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
);
typedef _OpenNative = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>);
typedef _DeriveNative = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Uint32,
);
typedef _DeriveDart = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  int,
);

/// `chain_id, msgs_json, fee_json, memo, account_number, sequence, public_key_hex,
/// eth_key_type, mode`. Shared by `zunia_build_sign_bytes` and `zunia_preview_tx`.
typedef _SignBytesNative = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Uint64,
  Uint64,
  Pointer<Utf8>,
  Uint8,
  Pointer<Utf8>,
);
typedef _SignBytesDart = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  int,
  int,
  Pointer<Utf8>,
  int,
  Pointer<Utf8>,
);

/// The same, plus `signature_hex`.
typedef _AssembleNative = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Uint64,
  Uint64,
  Pointer<Utf8>,
  Uint8,
  Pointer<Utf8>,
  Pointer<Utf8>,
);
typedef _AssembleDart = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  int,
  int,
  Pointer<Utf8>,
  int,
  Pointer<Utf8>,
  Pointer<Utf8>,
);

/// The same without a mode, because a simulation is always Direct.
typedef _SimulateNative = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Uint64,
  Uint64,
  Pointer<Utf8>,
  Uint8,
);
typedef _SimulateDart = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  int,
  int,
  Pointer<Utf8>,
  int,
);

/// `phrase, passphrase, chain_json, account_index, chain_id, msgs_json, fee_json, memo,
/// account_number, sequence, mode`.
typedef _SignTxNative = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Uint32,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Uint64,
  Uint64,
  Pointer<Utf8>,
);
typedef _SignTxDart = Pointer<Utf8> Function(
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  int,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  int,
  int,
  Pointer<Utf8>,
);

/// Thin FFI wrapper. Every returned secret string is copied into Dart and the native buffer
/// is freed immediately; callers must still avoid logging or persisting unlocked phrases.
///
/// Secrets going the other way are handled by [_withSecret], which overwrites the native buffer
/// before releasing it. An arena free does not clear what it frees, and a mnemonic left in
/// released heap outlives the call that needed it.
class ZuniaCore {
  ZuniaCore._(DynamicLibrary lib)
      : _free = lib.lookupFunction<_FreeFn, void Function(Pointer<Utf8>)>(
          'zunia_string_free',
        ),
        _version = lib.lookupFunction<_StringFn, Pointer<Utf8> Function()>(
          'zunia_kernel_version',
        ),
        _generate = lib.lookupFunction<_GenMnemonicNative, _GenMnemonicDart>(
          'zunia_generate_mnemonic',
        ),
        _seal = lib.lookupFunction<_SealNative, _SealNative>('zunia_seal_keyring'),
        _open = lib.lookupFunction<_OpenNative, _OpenNative>('zunia_open_keyring'),
        _derive =
            lib.lookupFunction<_DeriveNative, _DeriveDart>('zunia_derive_address'),
        _buildSignBytes = lib.lookupFunction<_SignBytesNative, _SignBytesDart>(
          'zunia_build_sign_bytes',
        ),
        _assembleTxRaw = lib.lookupFunction<_AssembleNative, _AssembleDart>(
          'zunia_assemble_tx_raw',
        ),
        _buildSimulateTx = lib.lookupFunction<_SimulateNative, _SimulateDart>(
          'zunia_build_simulate_tx',
        ),
        _signTx = lib.lookupFunction<_SignTxNative, _SignTxDart>('zunia_sign_tx'),
        _previewTx = lib.lookupFunction<_SignBytesNative, _SignBytesDart>(
          'zunia_preview_tx',
        );

  // The DynamicLibrary itself is not retained: Dart never unloads one, and every symbol was
  // resolved to a function pointer in the initializer list above.
  final void Function(Pointer<Utf8>) _free;
  final Pointer<Utf8> Function() _version;
  final _GenMnemonicDart _generate;
  final _SealNative _seal;
  final _OpenNative _open;
  final _DeriveDart _derive;
  final _SignBytesDart _buildSignBytes;
  final _AssembleDart _assembleTxRaw;
  final _SimulateDart _buildSimulateTx;
  final _SignTxDart _signTx;
  final _SignBytesDart _previewTx;

  /// Opens the platform-specific dynamic library shipped beside the app.
  static ZuniaCore open() {
    final DynamicLibrary lib;
    if (Platform.isAndroid) {
      lib = DynamicLibrary.open('libzunia_ffi.so');
    } else if (Platform.isIOS) {
      lib = DynamicLibrary.process();
    } else if (Platform.isMacOS) {
      lib = DynamicLibrary.open('libzunia_ffi.dylib');
    } else if (Platform.isLinux) {
      lib = DynamicLibrary.open('libzunia_ffi.so');
    } else {
      throw UnsupportedError('ZuniaCore is not supported on ${Platform.operatingSystem}');
    }
    return ZuniaCore._(lib);
  }

  String get kernelVersion => _read(_version());

  String generateMnemonic({int words = 12}) => _read(_generate(words));

  String sealKeyring({
    required String phrase,
    required String password,
    Map<String, Object?> metadata = const {},
  }) {
    return using((arena) {
      final meta = jsonEncode(metadata).toNativeUtf8(allocator: arena);
      return _withSecret(phrase, (p) => _withSecret(password, (pw) => _read(_seal(p, pw, meta))));
    });
  }

  String openKeyring({required String envelopeJson, required String password}) {
    return using((arena) {
      final e = envelopeJson.toNativeUtf8(allocator: arena);
      return _withSecret(password, (pw) => _read(_open(e, pw)));
    });
  }

  Map<String, dynamic> deriveAddress({
    required String phrase,
    String passphrase = '',
    required String chainJson,
    int accountIndex = 0,
  }) {
    final raw = using((arena) {
      final c = chainJson.toNativeUtf8(allocator: arena);
      return _withSecret(
        phrase,
        (p) => _withSecret(passphrase, (pp) => _read(_derive(p, pp, c, accountIndex))),
      );
    });
    return jsonDecode(raw) as Map<String, dynamic>;
  }

  /// The bytes the kernel must sign, hex encoded.
  ///
  /// Pure: no key material is involved and nothing is signed. [msgs] is the
  /// `[{ "typeUrl": ..., "value": { ... } }]` array `@zunialab/interchain` emits, with
  /// snake_case fields and every amount a decimal string.
  ///
  /// [mode] is required, not defaulted; see [ZuniaSignMode].
  String buildSignBytes({
    required String chainId,
    required List<Map<String, dynamic>> msgs,
    required ZuniaFee fee,
    String memo = '',
    required int accountNumber,
    required int sequence,
    required String publicKeyHex,
    bool ethKeyType = false,
    required ZuniaSignMode mode,
  }) {
    return using((arena) {
      final args = _TxArgs(arena, chainId, msgs, fee, memo, publicKeyHex);
      final m = mode.wire.toNativeUtf8(allocator: arena);
      return _read(_buildSignBytes(
        args.chainId,
        args.msgs,
        args.fee,
        args.memo,
        accountNumber,
        sequence,
        args.publicKey,
        ethKeyType ? 1 : 0,
        m,
      ));
    });
  }

  /// The broadcastable `TxRaw`, hex encoded, given a signature over [buildSignBytes]' output.
  ///
  /// Every argument except [signatureHex] must be exactly what was passed to [buildSignBytes],
  /// the mode included: the `auth_info` inside a `TxRaw` records the sign mode, so a Direct
  /// signature attached to Amino `auth_info` verifies against nothing.
  ///
  /// [signatureHex] is 64 bytes of `r||s`. An Ethereum-style 65-byte signature with the
  /// recovery id still attached is rejected rather than truncated.
  String assembleTxRaw({
    required String chainId,
    required List<Map<String, dynamic>> msgs,
    required ZuniaFee fee,
    String memo = '',
    required int accountNumber,
    required int sequence,
    required String publicKeyHex,
    bool ethKeyType = false,
    required ZuniaSignMode mode,
    required String signatureHex,
  }) {
    return using((arena) {
      final args = _TxArgs(arena, chainId, msgs, fee, memo, publicKeyHex);
      final m = mode.wire.toNativeUtf8(allocator: arena);
      final sig = signatureHex.toNativeUtf8(allocator: arena);
      return _read(_assembleTxRaw(
        args.chainId,
        args.msgs,
        args.fee,
        args.memo,
        accountNumber,
        sequence,
        args.publicKey,
        ethKeyType ? 1 : 0,
        m,
        sig,
      ));
    });
  }

  /// A `TxRaw` carrying a 64-byte zero signature, for `POST /cosmos/tx/v1beta1/simulate`.
  ///
  /// Never broadcastable: the zero signature verifies against nothing, which is the point.
  /// Simulation skips signature verification but the transaction must still decode and must
  /// still carry one signature per signer, so an empty signature list would be answered with a
  /// decode error instead of a gas estimate.
  String buildSimulateTx({
    required String chainId,
    required List<Map<String, dynamic>> msgs,
    required ZuniaFee fee,
    String memo = '',
    required int accountNumber,
    required int sequence,
    required String publicKeyHex,
    bool ethKeyType = false,
  }) {
    return using((arena) {
      final args = _TxArgs(arena, chainId, msgs, fee, memo, publicKeyHex);
      return _read(_buildSimulateTx(
        args.chainId,
        args.msgs,
        args.fee,
        args.memo,
        accountNumber,
        sequence,
        args.publicKey,
        ethKeyType ? 1 : 0,
      ));
    });
  }

  /// Derives, signs and assembles in one call, returning the broadcastable `TxRaw` as hex.
  ///
  /// The public key and the `ethsecp256k1` flag are read from [chainJson] rather than taken
  /// from the caller, so they cannot disagree with the key that actually signs. [chainId] must
  /// be the one [chainJson] names: a mismatch means deriving a key for one chain and signing a
  /// document for another, and the kernel refuses it.
  ///
  /// The phrase and passphrase buffers handed to the kernel are overwritten before they are
  /// released, and the kernel zeroizes the seed and the derived key on its own side.
  String signTx({
    required String phrase,
    String passphrase = '',
    required String chainJson,
    int accountIndex = 0,
    required String chainId,
    required List<Map<String, dynamic>> msgs,
    required ZuniaFee fee,
    String memo = '',
    required int accountNumber,
    required int sequence,
    required ZuniaSignMode mode,
  }) {
    return using((arena) {
      final args = _TxArgs(arena, chainId, msgs, fee, memo, '');
      final chain = chainJson.toNativeUtf8(allocator: arena);
      final m = mode.wire.toNativeUtf8(allocator: arena);
      return _withSecret(
        phrase,
        (p) => _withSecret(
          passphrase,
          (pp) => _read(_signTx(
            p,
            pp,
            chain,
            accountIndex,
            args.chainId,
            args.msgs,
            args.fee,
            args.memo,
            accountNumber,
            sequence,
            m,
          )),
        ),
      );
    });
  }

  /// What the approval screen shows, without signing anything.
  ///
  /// Built from the same transaction [buildSignBytes] would encode, so the screen and the
  /// broadcast cannot drift; see [ZuniaSigningPreview.signBytesHash].
  ZuniaSigningPreview previewTx({
    required String chainId,
    required List<Map<String, dynamic>> msgs,
    required ZuniaFee fee,
    String memo = '',
    required int accountNumber,
    required int sequence,
    required String publicKeyHex,
    bool ethKeyType = false,
    required ZuniaSignMode mode,
  }) {
    final raw = using((arena) {
      final args = _TxArgs(arena, chainId, msgs, fee, memo, publicKeyHex);
      final m = mode.wire.toNativeUtf8(allocator: arena);
      return _read(_previewTx(
        args.chainId,
        args.msgs,
        args.fee,
        args.memo,
        accountNumber,
        sequence,
        args.publicKey,
        ethKeyType ? 1 : 0,
        m,
      ));
    });
    return ZuniaSigningPreview.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  /// Copies a secret into native memory for the duration of [body], then overwrites the buffer
  /// before releasing it.
  ///
  /// `toNativeUtf8` plus an arena would free the mnemonic without clearing it, leaving it in
  /// released heap for as long as nothing reuses the page. The cost here is one copy.
  static T _withSecret<T>(String value, T Function(Pointer<Utf8>) body) {
    final units = utf8.encode(value);
    final size = units.length + 1;
    final buffer = calloc<Uint8>(size);
    final bytes = buffer.asTypedList(size);
    bytes.setRange(0, units.length, units);
    try {
      return body(buffer.cast<Utf8>());
    } finally {
      bytes.fillRange(0, size, 0);
      calloc.free(buffer);
    }
  }

  /// Copies a returned string into Dart, frees the native buffer, and turns the C ABI's error
  /// encoding into an exception.
  ///
  /// The free happens in a `finally` so a thrown error still releases the buffer; the leak
  /// would otherwise be a leak of whatever the call was about.
  String _read(Pointer<Utf8> ptr) {
    if (ptr == nullptr) {
      throw const ZuniaCoreException('zunia_ffi returned a null string');
    }
    try {
      final value = ptr.toDartString();
      if (value.startsWith('error:')) {
        throw ZuniaCoreException(value.substring(6).trim());
      }
      return value;
    } finally {
      _free(ptr);
    }
  }
}

/// The six strings every transaction entry point shares, allocated once per call.
///
/// Exists so the JSON encoding lives in one place: a caller passes Dart values and never hand
/// builds a wire string, which is what keeps `gas_limit`, the amount strings and the
/// `{ typeUrl, value }` envelope from being spelled differently at each call site.
class _TxArgs {
  _TxArgs(
    Allocator arena,
    String chainIdValue,
    List<Map<String, dynamic>> msgsValue,
    ZuniaFee feeValue,
    String memoValue,
    String publicKeyHexValue,
  )   : chainId = chainIdValue.toNativeUtf8(allocator: arena),
        msgs = jsonEncode(msgsValue).toNativeUtf8(allocator: arena),
        fee = jsonEncode(feeValue.toJson()).toNativeUtf8(allocator: arena),
        memo = memoValue.toNativeUtf8(allocator: arena),
        publicKey = publicKeyHexValue.toNativeUtf8(allocator: arena);

  final Pointer<Utf8> chainId;
  final Pointer<Utf8> msgs;
  final Pointer<Utf8> fee;
  final Pointer<Utf8> memo;
  final Pointer<Utf8> publicKey;
}
