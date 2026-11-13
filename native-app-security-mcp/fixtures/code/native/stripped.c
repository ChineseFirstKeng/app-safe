__attribute__((noinline)) static const char *fixture_private_helper(void) {
    return "fixture-private-native-literal";
}

__attribute__((noinline, visibility("default"))) int fixture_stripped_entry(unsigned index) {
    const char *value = fixture_private_helper();
    return value[index & 7];
}

#ifdef FIXTURE_EXECUTABLE
int main(void) { return fixture_stripped_entry(0); }
#endif
