// CocoaPods needs a compile unit for this plugin. The kernel's functions themselves come from
// the force-loaded libzunia_ffi.a (see zunia_core.podspec) and are found by Dart at run time.
#import <Foundation/Foundation.h>

@interface ZuniaCorePlugin : NSObject
@end

@implementation ZuniaCorePlugin
@end
