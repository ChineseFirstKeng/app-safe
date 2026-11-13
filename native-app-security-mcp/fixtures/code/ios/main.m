#import <Foundation/Foundation.h>

@interface FixtureEcho : NSObject
+ (NSString *)echo:(NSString *)value;
@end
@implementation FixtureEcho
+ (NSString *)echo:(NSString *)value {
    return [value stringByAppendingString:@"fixture-objc-literal"];
}
@end

__attribute__((noinline)) const char *fixture_native_helper(void) {
    return "fixture-native-literal";
}
__attribute__((noinline)) const char *fixture_native_entry(void) {
    return fixture_native_helper();
}
int main(void) {
    @autoreleasepool {
        NSString *value = [FixtureEcho echo:@"input"];
        return (int)[value length] + fixture_native_entry()[0];
    }
}
