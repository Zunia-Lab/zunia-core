/// High-level Dart API over the Zunia native kernel.
///
/// Native libraries are downloaded from a pinned GitHub Release tag by mobile CI
/// (`scripts/fetch-native.sh` in zunia-mobile). This package only declares the FFI surface.
library;

export 'src/zunia_core.dart';
