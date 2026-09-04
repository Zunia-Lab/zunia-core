import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

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

/// Thin FFI wrapper. Every returned secret string is copied into Dart and the native buffer
/// is freed immediately; callers must still avoid logging or persisting unlocked phrases.
class ZuniaCore {
  ZuniaCore._(this._lib)
      : _free = _lib.lookupFunction<_FreeFn, void Function(Pointer<Utf8>)>(
          'zunia_string_free',
        ),
        _version = _lib.lookupFunction<_StringFn, Pointer<Utf8> Function()>(
          'zunia_kernel_version',
        ),
        _generate = _lib.lookupFunction<_GenMnemonicNative, _GenMnemonicDart>(
          'zunia_generate_mnemonic',
        ),
        _seal = _lib.lookupFunction<_SealNative, _SealNative>('zunia_seal_keyring'),
        _open = _lib.lookupFunction<_OpenNative, _OpenNative>('zunia_open_keyring'),
        _derive =
            _lib.lookupFunction<_DeriveNative, _DeriveDart>('zunia_derive_address');

  final DynamicLibrary _lib;
  final void Function(Pointer<Utf8>) _free;
  final Pointer<Utf8> Function() _version;
  final _GenMnemonicDart _generate;
  final _SealNative _seal;
  final _OpenNative _open;
  final _DeriveDart _derive;

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
      final p = phrase.toNativeUtf8(allocator: arena);
      final pw = password.toNativeUtf8(allocator: arena);
      final meta = jsonEncode(metadata).toNativeUtf8(allocator: arena);
      return _read(_seal(p, pw, meta));
    });
  }

  String openKeyring({required String envelopeJson, required String password}) {
    return using((arena) {
      final e = envelopeJson.toNativeUtf8(allocator: arena);
      final pw = password.toNativeUtf8(allocator: arena);
      return _read(_open(e, pw));
    });
  }

  Map<String, dynamic> deriveAddress({
    required String phrase,
    String passphrase = '',
    required String chainJson,
    int accountIndex = 0,
  }) {
    final raw = using((arena) {
      final p = phrase.toNativeUtf8(allocator: arena);
      final pp = passphrase.toNativeUtf8(allocator: arena);
      final c = chainJson.toNativeUtf8(allocator: arena);
      return _read(_derive(p, pp, c, accountIndex));
    });
    return jsonDecode(raw) as Map<String, dynamic>;
  }

  String _read(Pointer<Utf8> ptr) {
    if (ptr == nullptr) {
      throw StateError('zunia_ffi returned a null string');
    }
    try {
      final value = ptr.toDartString();
      if (value.startsWith('error:')) {
        throw StateError(value.substring(7).trim());
      }
      return value;
    } finally {
      _free(ptr);
    }
  }
}
