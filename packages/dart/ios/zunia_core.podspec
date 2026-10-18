Pod::Spec.new do |s|
  s.name             = 'zunia_core'
  s.version          = '0.1.1'
  s.summary          = 'Zunia wallet kernel FFI bindings'
  s.description      = 'Links the prebuilt ZuniaCore kernel into the plugin framework for DynamicLibrary.process().'
  s.homepage         = 'https://zunialab.com'
  s.license          = { :type => 'Apache-2.0' }
  s.author           = { 'Zunia Lab' => 'support@zunialab.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
  s.swift_version = '5.0'

  # The kernel is a static library per SDK inside Frameworks/ZuniaCore.xcframework. It is
  # force-loaded into this plugin's own framework, which then exports every kernel function;
  # Dart finds them through DynamicLibrary.process() once the app has loaded the framework.
  # Force-loading matters: nothing compiled calls these functions, so a plain link would keep
  # none of them. The released kernel has an arm64 simulator slice only (Apple silicon): an
  # x86_64 simulator build of this framework links without it, and the app reports the kernel
  # missing there rather than failing to build.
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    'ZUNIA_FFI_SLICE[sdk=iphonesimulator*]' => 'ios-arm64-simulator',
    'ZUNIA_FFI_SLICE[sdk=iphoneos*]' => 'ios-arm64',
    'OTHER_LDFLAGS' => '$(inherited) -force_load "${PODS_TARGET_SRCROOT}/Frameworks/ZuniaCore.xcframework/$(ZUNIA_FFI_SLICE)/libzunia_ffi.a"',
  }
  s.preserve_paths = 'Frameworks/**/*'
end
