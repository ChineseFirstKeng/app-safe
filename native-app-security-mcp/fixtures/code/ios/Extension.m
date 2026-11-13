#import <Foundation/Foundation.h>

@interface FixtureExtension : NSObject
+ (NSString *)value;
@end
@implementation FixtureExtension
+ (NSString *)value { return @"fixture-extension-literal"; }
@end

int main(void) {
    @autoreleasepool { return (int)[[FixtureExtension value] length]; }
}
