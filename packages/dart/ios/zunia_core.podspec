Pod::Spec.new do |s|
  s.name             = 'zunia_core'
  s.version          = '0.1.0'
  s.summary          = 'Zunia wallet kernel FFI bindings'
  s.description      = 'Loads the prebuilt ZuniaCore native library via DynamicLibrary.process().'
  s.homepage         = 'https://zunialab.com'
  s.license          = { :type => 'Apache-2.0' }
  s.author           = { 'Zunia Lab' => 'support@zunialab.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # Optional vendored framework: when present next to this podspec OR when the app
  # has linked ZuniaCore.xcframework into the Runner, DynamicLibrary.process() works.
  # Do NOT fail pod install if the xcframework is missing.
  framework = File.join(__dir__, 'Frameworks', 'ZuniaCore.xcframework')
  if File.directory?(framework)
    s.vendored_frameworks = 'Frameworks/ZuniaCore.xcframework'
  end
end
